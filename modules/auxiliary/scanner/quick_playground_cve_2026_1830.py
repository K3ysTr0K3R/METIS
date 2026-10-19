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

ENDPOINT = "/wp-json/quickplayground/v1/upload_image/default"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class QuickPlaygroundScanner(Auxiliary):
    NAME = "WordPress Quick Playground RCE Scanner (CVE-2026-1830)"
    DESCRIPTION = (
        "Detects the Quick Playground WordPress plugin (<= 1.3.1) REST API "
        "endpoint that allows unauthenticated file upload via sync_code "
        "validation. Checks for the /wp-json/quickplayground/v1/ upload "
        "endpoint without uploading a webshell."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "great"
    DISCLOSED = "2026-04-08"
    CHECK = True
    REFERENCES = [
        "CVE-2026-1830",
        "https://vuldb.com/cve/CVE-2026-1830",
        "https://www.exploit-db.com/exploits/52596",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
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

    def _post(self, host, path, payload):
        url = self._base_url(host) + path
        ctx = ssl._create_unverified_context()
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except urllib.error.URLError:
            raise

    def _probe(self, host):
        payload = {
            "sync_code": "metis_test_invalid",
            "filename": "metis_probe.txt",
            "base64": "bWV0aXM=",
        }
        try:
            st, body = self._post(host, ENDPOINT, payload)
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)

        if st in (200, 400, 403):
            try:
                data = json.loads(body.decode(errors="replace"))
            except ValueError:
                return HostResult(host, "safe", "non-json response")

            msg = (data.get("message") or "").lower()
            code = (data.get("code") or "").lower()

            if "sync" in msg or "sync" in code or "invalid" in msg:
                return HostResult(host, "vulnerable", "endpoint reachable")

        if st == 404:
            return HostResult(host, "safe", "endpoint not found")

        return HostResult(host, "safe", "HTTP " + str(st))

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="WordPress",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2026-1830",
            info=h.detail,
        )

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host) + ENDPOINT))
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

        print(colors.info("scanning " + str(len(targets)) + " host(s) with " + str(threads) + " threads"))
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
