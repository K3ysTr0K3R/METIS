import re
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

DEFAULT_TERMINAL_PATH = "/terminal/ws"
VULN_VERSION_CAP = (0, 20, 4)


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    version: str = ""


class MarimoTerminalWsDetect(Auxiliary):
    NAME = "marimo Terminal WebSocket Detection Scanner (CVE-2026-39987)"
    DESCRIPTION = (
        "Detects the unauthenticated /terminal/ws WebSocket endpoint in "
        "marimo <= 0.20.4. The handler calls websocket.accept() and "
        "pty.fork() without validate_auth(), unlike sibling WebSocket "
        "handlers, exposing an interactive PTY shell to any anonymous "
        "client. Confirms the vulnerability by sending a benign echo "
        "marker through the websocket. No shell is spawned and no "
        "persistent state is created."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-01-10"
    CHECK = True
    REFERENCES = [
        "CVE-2026-39987",
        "https://github.com/marimo-team/marimo/security/advisories",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=8080, type=int, description="marimo HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS/WSS"),
        Option("PATH", default="/",
               description="base path prefix (blank = root)"),
        Option("TIMEOUT", default=10.0, type=float,
               description="websocket/HTTP timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first vulnerable host"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _base(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return f"{scheme}://{host}:{self.options['RPORT']}"

    def _ws_url(self, host):
        base = self._base(host)
        prefix = (self.options["PATH"] or "").rstrip("/")
        path = prefix + DEFAULT_TERMINAL_PATH
        ws_scheme = "wss" if base.startswith("https") else "ws"
        netloc = base.split("://", 1)[1]
        return f"{ws_scheme}://{netloc}{path}"

    def _open_ws(self, host):
        try:
            import websocket
        except ImportError:
            raise RuntimeError(
                "websocket-client is required: pip install websocket-client"
            )

        sslopt = {"cert_reqs": ssl.CERT_NONE} if self.options["SSL"] else None
        try:
            return websocket.create_connection(
                self._ws_url(host),
                timeout=self.options["TIMEOUT"],
                sslopt=sslopt,
            )
        except Exception as e:
            raise RuntimeError(f"ws connect failed: {type(e).__name__}: {e}") from e

    def _drain(self, ws, idle=0.3):
        ws.settimeout(idle)
        while True:
            try:
                if not ws.recv():
                    return
            except Exception:
                return

    def _version_from_homepage(self, host):
        url = self._base(host) + (self.options["PATH"] or "/")
        ctx = ssl._create_unverified_context() if self.options["SSL"] else None
        try:
            with urllib.request.urlopen(
                url, timeout=self.options["TIMEOUT"], context=ctx
            ) as r:
                body = r.read(200_000).decode(errors="replace")
        except (urllib.error.URLError, OSError):
            return ""

        for pat in (
            r'"version"\s*:\s*"(\d+\.\d+\.\d+(?:[a-z0-9.\-]*)?)"',
            r'marimo[^0-9]{0,8}(\d+\.\d+\.\d+)',
            r'"marimo"\s*:\s*"(\d+\.\d+\.\d+)"',
        ):
            m = re.search(pat, body, re.I)
            if m:
                return m.group(1)
        return ""

    @staticmethod
    def _version_tuple(v):
        try:
            return tuple(int(x) for x in v.split(".")[:3])
        except (ValueError, AttributeError):
            return (0,)

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            ws = self._open_ws(host)
        except RuntimeError as e:
            result.detail = str(e)
            return result

        try:
            self._drain(ws, idle=0.5)

            marker = "METIS_MARIMO_" + hex(int(time.time()))[-6:]
            ws.send(f"echo {marker}\n")
            time.sleep(1.0)

            out = ""
            ws.settimeout(0.3)
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    chunk = ws.recv()
                    if not chunk:
                        break
                    out += (
                        chunk if isinstance(chunk, str)
                        else chunk.decode(errors="replace")
                    )
                    if marker in out:
                        break
                except Exception:
                    break

            if marker in out:
                version = self._version_from_homepage(host)
                result.version = version
                result.state = "vulnerable"
                if version:
                    result.detail = "terminal WS accepted anonymous commands (v" + version + ")"
                else:
                    result.detail = "terminal WS accepted anonymous commands"
                return result

            result.state = "safe"
            result.detail = "terminal WS reachable but marker not returned"
            return result

        except Exception as e:
            result.detail = f"{type(e).__name__}: {e}"
            return result
        finally:
            try:
                ws.close()
            except Exception:
                pass

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        banner = "marimo"
        if h.version:
            banner += " " + h.version
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner=banner,
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2026-39987",
            info=h.detail,
        )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        print(colors.info("check: probing " + self._ws_url(host)))
        print(colors.dimmed("  path: " + DEFAULT_TERMINAL_PATH))

        r = self._probe(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            return CheckResult.VULNERABLE
        if r.state == "safe":
            print(colors.safe("check: " + host + " not vulnerable (" + r.detail + ")"))
            return CheckResult.SAFE
        print(colors.warn("check: " + host + " unknown (" + r.detail + ")"))
        return CheckResult.UNKNOWN

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info(
            "scanning " + str(len(targets)) + " host(s) with "
            + str(threads) + " threads"
        ))

        bar = ProgressBar(total=len(targets), prefix="scan")
        hits = []
        clean = 0
        unknown = 0
        aborted = False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._probe, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        r = fut.result()
                    except Exception:
                        unknown += 1
                        continue

                    if r.state == "vulnerable":
                        hits.append(r)
                        bar.log(colors.vuln(r.host + " - " + r.detail))
                        if workspace_active:
                            self._record_host_result(r)
                        if stop_first:
                            aborted = True
                            for f in futures:
                                f.cancel()
                            break
                    elif r.state == "safe":
                        clean += 1
                    else:
                        unknown += 1
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  vulnerable:   " + colors.green(str(len(hits))))
        print("  not vuln:     " + colors.dimmed(str(clean)))
        print("  unknown:      " + colors.warn(str(unknown)))
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
                print("    " + colors.vuln(h.host) + "  " + colors.dimmed(h.detail))

        return hits
