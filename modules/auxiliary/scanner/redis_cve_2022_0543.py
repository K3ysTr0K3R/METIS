import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

try:
    import redis
except ImportError:
    redis = None

from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

DETECT_PAYLOAD = (
    "return (type(package)=='table' and type(package.loadlib)=='function') "
    "and 'vuln' or 'safe'"
)

@dataclass
class HostResult:
    host: str
    port: int
    vulnerable: bool = False
    error: str | None = None

class RedisCve20220543Scanner(Auxiliary):
    NAME = "Redis CVE-2022-0543 Scanner"
    DESCRIPTION = (
        "Detects Redis instances vulnerable to CVE-2022-0543 (Debian/Ubuntu "
        "Lua sandbox escape). Non-destructive. Supports single hosts, comma "
        "lists, CIDR, ranges, and file: target specs."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2022-02-18"
    CHECK = True
    REFERENCES = [
        "CVE-2022-0543",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=6379, type=int, description="Redis port"),
        Option("PASSWORD", default=None, description="Redis AUTH password (optional)"),
        Option("TIMEOUT", default=3.0, type=float, description="per-connection timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first vulnerable host"),
    ]

    def _expand_targets(self) -> list[str]:
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info(f"target list -> {len(hosts)} hosts"))
        return hosts

    def _probe(self, host: str) -> HostResult:
        if redis is None:
            return HostResult(host=host, port=self.options["RPORT"], error="redis lib missing")
        port = self.options["RPORT"]
        res = HostResult(host=host, port=port)
        try:
            r = redis.Redis(
                host=host, port=port,
                password=self.options["PASSWORD"] or None,
                socket_connect_timeout=self.options["TIMEOUT"],
                socket_timeout=self.options["TIMEOUT"],
            )
            result = r.eval(DETECT_PAYLOAD, 0)
            if isinstance(result, bytes):
                result = result.decode(errors="replace")
            res.vulnerable = (result == "vuln")
            if not res.vulnerable:
                res.error = f"not vulnerable ({result})"
        except redis.exceptions.AuthenticationError:
            res.error = "auth required"
        except redis.exceptions.ConnectionError:
            res.error = "connection"
        except (OSError, Exception) as e:
            res.error = type(e).__name__
        return res

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, h.port,
            proto="tcp", state="open",
            name="redis", banner="",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2022-0543",
            info="Lua sandbox escape via package.loadlib",
        )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                f"check on multiple targets: probing only {targets[0]} "
                f"(use 'run' to scan all {len(targets)})"
            ))
        host = targets[0]
        print(colors.info(f"check: probing {host}:{self.options['RPORT']}"))
        res = self._probe(host)
        if res.vulnerable:
            print(colors.vuln(f"check: {host} vulnerable"))
            return CheckResult.VULNERABLE
        if res.error:
            print(colors.safe(f"check: {host} not vulnerable ({res.error})"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info(f"scanning {len(targets)} host(s) with {threads} threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits, errors, aborted = [], 0, False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._probe, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        res = fut.result()
                    except Exception:
                        errors += 1
                        continue
                    if res.vulnerable:
                        hits.append(res)
                        bar.log(colors.vuln(f"{res.host}:{res.port} vulnerable"))
                        if workspace_active:
                            self._record_host_result(res)
                        if stop_first:
                            aborted = True
                            for f in futures:
                                f.cancel()
                            break
                    elif res.error:
                        errors += 1
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print(f"  targets:      {len(targets)}")
        print(f"  vulnerable:   {colors.green(str(len(hits)))}")
        print(f"  errors/skips: {colors.dimmed(str(errors))}")
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} vuln(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  vulnerable hosts:"))
            for h in hits:
                print(f"    {colors.vuln(h.host)}:{h.port}")
        return hits
