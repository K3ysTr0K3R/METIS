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

FAVICON_HASHES = {
    "fortinet-fortigate": "945408572",
    "fortinet-fortimail": "999357577",
}

TITLE_PATTERNS = {
    "fortigate": "fortigate",
    "fortimail": "fortimail",
    "fortiweb": "fortiweb",
    "fortimanager": "fortimanager",
    "fortianalyzer": "fortianalyzer",
    "fortiproxy": "fortiproxy",
    "forticlient": "forticlient",
}

BODY_SIGNATURES = {
    "fortigate": ["fortigate", "fortios"],
    "fortimail": ["fortimail"],
    "fortiweb": ["fortiweb"],
    "fortimanager": ["fortimanager"],
    "fortianalyzer": ["fortianalyzer"],
    "fortiproxy": ["fortiproxy"],
    "forticlient": ["forticlient", "forticlientems"],
}

HEADER_SIGNATURES = {
    "fortigate": ["x-frame-options"],
    "fortiweb": ["fortiweb"],
}


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    product: str = ""
    version: str = ""


class FortinetDetect(Auxiliary):
    NAME = "Fortinet Product Detector"
    DESCRIPTION = (
        "Fingerprints Fortinet product families (FortiGate, FortiMail, "
        "FortiWeb, FortiManager, FortiAnalyzer, FortiProxy, FortiClient EMS) "
        "by probing the HTTPS management interface. Checks response titles, "
        "body signatures, response headers, and known favicon hashes."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True
    REFERENCES = [
        "https://www.fortinet.com/",
        "https://github.com/BishopFox/Favicons",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=443, type=int, description="HTTPS port"),
        Option("SSL", default=True, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first confirmed host"),
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

    def _get(self, host, path):
        url = self._base_url(host) + path
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Accept", "text/html,application/xhtml+xml,*/*")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def _match_from_text(self, text):
        lowered = text.lower()
        for product, sigs in BODY_SIGNATURES.items():
            for sig in sigs:
                if sig in lowered:
                    return product
        return ""

    def _match_from_title(self, body):
        import re
        m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
        if not m:
            return ""
        title = m.group(1).lower()
        for product, sig in TITLE_PATTERNS.items():
            if sig in title:
                return product
        return ""

    def _match_favicon(self, host):
        try:
            st, raw, _ = self._get(host, "/favicon.ico")
        except urllib.error.URLError:
            return ""
        if st != 200 or not raw:
            return ""
        try:
            import mmh3
            import base64
            hash_val = mmh3.hash(base64.encodebytes(raw))
            hash_str = str(hash_val)
            for product, known in FAVICON_HASHES.items():
                if hash_str == known:
                    return product.replace("fortinet-", "")
        except Exception:
            pass
        return ""

    def _extract_version(self, body):
        import re
        patterns = [
            r'FortiOS\s+v?(\d+\.\d+\.\d+)',
            r'FortiWeb\s+v?(\d+\.\d+\.\d+)',
            r'FortiMail\s+v?(\d+\.\d+\.\d+)',
            r'v?(\d+\.\d+\.\d+)[,\s]*build\d+',
        ]
        for pat in patterns:
            m = re.search(pat, body, re.I)
            if m:
                return m.group(1)
        return ""

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            st, raw, headers = self._get(host, "/")
        except urllib.error.URLError as e:
            result.detail = type(e).__name__
            return result

        body = raw.decode(errors="replace") if isinstance(raw, bytes) else raw

        if st not in (200, 302, 401, 403):
            result.detail = "HTTP " + str(st)
            return result

        product = ""

        product = self._match_from_title(body)
        if not product:
            product = self._match_from_text(body)

        if not product:
            for name, sigs in HEADER_SIGNATURES.items():
                blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
                for sig in sigs:
                    if sig in blob:
                        product = name
                        break
                if product:
                    break

        if not product:
            product = self._match_favicon(host)

        if product:
            result.state = "confirmed"
            result.product = product
            result.version = self._extract_version(body)
            detail = "Fortinet " + product
            if result.version:
                detail += " v" + result.version
            result.detail = detail
            return result

        result.detail = "not Fortinet"
        return result

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        banner = h.detail
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name="https", banner=banner,
        )
        bits = ["product=" + h.product]
        if h.version:
            bits.append("version=" + h.version)
        bits.append("detail=" + h.detail)
        self.note(" ".join(bits), address=h.host, kind="fortinet_info")

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))
        r = self._probe(host)

        if r.state == "confirmed":
            print(colors.vuln("check: " + host + " - " + r.detail))
            return CheckResult.VULNERABLE

        print(colors.safe("check: " + host + " not Fortinet (" + r.detail + ")"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info("scanning " + str(len(targets)) + " host(s) with " + str(threads) + " threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits = []
        clean = 0
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
                        clean += 1
                        continue

                    if r.state == "confirmed":
                        hits.append(r)
                        bar.log(colors.vuln(r.host + " — " + r.detail))
                        if workspace_active:
                            self._record_host_result(r)
                        if stop_first:
                            aborted = True
                            for f in futures:
                                f.cancel()
                            break
                    else:
                        clean += 1
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  fortinet:     " + colors.green(str(len(hits))))
        print("  not fortinet: " + colors.dimmed(str(clean)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} note(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  fortinet hosts:"))
            for h in hits:
                print("    " + colors.vuln(h.host) + "  " + colors.dimmed(h.detail))

        return hits
