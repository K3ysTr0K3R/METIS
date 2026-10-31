import json
import re
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

BATCH_PATH = "/?rest_route=/batch/v1"

BATCH_PAYLOAD = json.dumps({
    "requests": [
        {"method": "POST", "path": "///"},
        {"method": "POST", "path": "/wp/v2/posts"},
        {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
        {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
    ]
}).encode()

VULN_MARKERS = (
    b"parse_path_failed",
    b"block_cannot_read",
    b"rest_batch_not_allowed",
)

WP_BODY_SIGNATURES = (
    b"wp-content",
    b"wp-includes",
    b"rest_route",
    b"wp-json",
)


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    markers_found: str = ""


class WordPressBatchRouteConfusionDetect(Auxiliary):
    NAME = "WordPress Batch-Route Confusion Detection Scanner (CVE-2026-63030)"
    DESCRIPTION = (
        "Detects WordPress core 6.9.0-6.9.4 and 7.0.0-7.0.1 vulnerable to "
        "the pre-auth batch-route confusion in /?rest_route=/batch/v1 "
        "(CVE-2026-63030). The module first confirms the target is "
        "WordPress, then sends a malformed nested batch request that "
        "desynchronizes the batch router. A vulnerable instance returns "
        "HTTP 207 with parse_path_failed, block_cannot_read, and "
        "rest_batch_not_allowed error codes. No SQL is executed and no "
        "timing oracle is used. Detection only - non-destructive."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-07-15"
    CHECK = True
    REFERENCES = [
        "CVE-2026-63030",
        "CVE-2026-60137",
        "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q",
        "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf",
        "https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core",
        "https://www.aikido.dev/blog/unauthenticated-rce-in-wordpress-wp2shell",
        "https://wordpress.org/news/2026/07/wordpress-7-0-2-release/",
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

    def _get_root(self, host):
        url = self._base_url(host) + "/"
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with urllib.request.urlopen(
                req, timeout=self.options["TIMEOUT"], context=ctx
            ) as r:
                headers = {k.lower(): v for k, v in r.headers.items()}
                body = r.read(200_000)
                return r.status, headers, body
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            body = e.read(200_000)
            return e.code, headers, body
        except urllib.error.URLError:
            raise

    def _post_batch(self, host):
        url = self._base_url(host) + BATCH_PATH
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url, data=BATCH_PAYLOAD, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(
                req, timeout=self.options["TIMEOUT"], context=ctx
            ) as r:
                headers = {k.lower(): v for k, v in r.headers.items()}
                body = r.read(200_000)
                return r.status, headers, body
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            body = e.read(200_000)
            return e.code, headers, body
        except urllib.error.URLError:
            raise

    def _is_wordpress(self, headers, body):
        blob = body.lower()
        for sig in WP_BODY_SIGNATURES:
            if sig in blob:
                return True
        header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()
        if "rest_route" in header_blob or "wp-json" in header_blob:
            return True
        return False

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            st, headers, body = self._get_root(host)
        except urllib.error.URLError as e:
            result.detail = type(e).__name__
            return result

        if not self._is_wordpress(headers, body):
            result.state = "safe"
            result.detail = "not WordPress"
            return result

        try:
            st2, headers2, body2 = self._post_batch(host)
        except urllib.error.URLError as e:
            result.detail = "batch request failed (" + type(e).__name__ + ")"
            return result

        content_type = headers2.get("content-type", "")
        if "application/json" not in content_type:
            result.state = "safe"
            result.detail = "batch response not JSON (content-type=" + content_type + ")"
            return result

        if st2 != 207:
            result.state = "safe"
            result.detail = "batch endpoint returned HTTP " + str(st2)
            return result

        found = []
        for marker in VULN_MARKERS:
            if marker in body2:
                found.append(marker.decode())

        if len(found) == len(VULN_MARKERS):
            result.state = "vulnerable"
            result.markers_found = ",".join(found)
            result.detail = "route confusion confirmed (" + ", ".join(found) + ")"
            return result

        if found:
            result.state = "safe"
            result.detail = (
                "partial markers (" + ",".join(found)
                + ") - likely patched or WAF filtering"
            )
            return result

        result.state = "safe"
        result.detail = "no route confusion markers"
        return result

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
            refs="CVE-2026-63030",
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
        print(colors.dimmed("  step 1: confirm WordPress"))
        print(colors.dimmed("  step 2: POST " + BATCH_PATH))

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
