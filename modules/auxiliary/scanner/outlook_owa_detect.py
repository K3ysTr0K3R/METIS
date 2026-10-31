import base64
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

OWA_PATHS = [
    "/owa/",
    "/owa/auth/logon.aspx",
    "/owa/auth/logon.aspx?replaceCurrent=1&url=/owa/",
]

FINGERPRINT_HEADERS = [
    "x-owa-version",
    "x-feserver",
]

OWA_FAVICON_HASHES = {
    "-1249852061",
    "-368490461",
}


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    version: str = ""
    frontend: str = ""


class OutlookOWADetect(Auxiliary):
    NAME = "Outlook Web App Detection Scanner"
    DESCRIPTION = (
        "Detects Microsoft Outlook Web App (OWA) / Exchange Server "
        "installations by probing the /owa/ endpoint and matching "
        "authoritative response headers (X-OWA-Version, X-FEServer). "
        "Falls back to a known OWA favicon mmh3 hash when headers are "
        "stripped by a reverse proxy. Detection only - no exploitation, "
        "no authentication attempts, no body-signature matching."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "info"
    CHECK = True
    REFERENCES = [
        "https://learn.microsoft.com/en-us/exchange/architecture/client-access/owa",
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposed-panels/microsoft-exchange-login.yaml",
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/favicon-detect.yaml",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=443, type=int, description="HTTPS port"),
        Option("SSL", default=True, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers"),
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
            with urllib.request.urlopen(
                req, timeout=self.options["TIMEOUT"], context=ctx
            ) as r:
                headers = {k.lower(): v for k, v in r.headers.items()}
                return r.status, headers
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            return e.code, headers
        except urllib.error.URLError:
            raise

    def _get_bytes(self, host, path):
        url = self._base_url(host) + path
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with urllib.request.urlopen(
                req, timeout=self.options["TIMEOUT"], context=ctx
            ) as r:
                return r.status, r.read(200_000)
        except urllib.error.HTTPError as e:
            return e.code, e.read(200_000)
        except urllib.error.URLError:
            raise

    def _favicon_hash(self, host):
        try:
            st, body = self._get_bytes(host, "/favicon.ico")
        except (urllib.error.URLError, OSError):
            return ""
        if st != 200 or not body:
            return ""
        try:
            import mmh3
            return str(mmh3.hash(base64.encodebytes(body)))
        except ImportError:
            return ""

    def _probe(self, host):
        result = HostResult(host=host)

        for path in OWA_PATHS:
            try:
                st, headers = self._get(host, path)
            except urllib.error.URLError as e:
                result.detail = type(e).__name__
                return result

            version = ""
            frontend = ""
            for h in FINGERPRINT_HEADERS:
                if h in headers:
                    if h == "x-owa-version":
                        version = headers[h]
                    elif h == "x-feserver":
                        frontend = headers[h]

            if version or frontend:
                result.state = "confirmed"
                result.version = version
                result.frontend = frontend
                parts = []
                if version:
                    parts.append("v" + version)
                if frontend:
                    parts.append("fe=" + frontend)
                result.detail = "OWA detected" + (
                    " (" + " | ".join(parts) + ")" if parts else ""
                )
                return result

        fh = self._favicon_hash(host)
        if fh and fh in OWA_FAVICON_HASHES:
            result.state = "confirmed"
            result.detail = "OWA detected (favicon hash " + fh + ")"
            return result

        result.state = "safe"
        result.detail = "no OWA fingerprint headers"
        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        banner = "Outlook Web App"
        if h.version:
            banner += " " + h.version
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner=banner,
        )
        bits = ["detected=OWA"]
        if h.version:
            bits.append("version=" + h.version)
        if h.frontend:
            bits.append("frontend=" + h.frontend)
        self.note(" ".join(bits), address=h.host, kind="outlook_owa")

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host) + "/owa/"))

        r = self._probe(host)

        if r.state == "confirmed":
            print(colors.good("check: " + host + " - " + r.detail))
            return CheckResult.UNKNOWN
        if r.state == "safe":
            print(colors.safe("check: " + host + " not OWA (" + r.detail + ")"))
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

                    if r.state == "confirmed":
                        hits.append(r)
                        bar.log(colors.good(r.host + " - " + r.detail))
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
        print("  OWA:          " + colors.green(str(len(hits))))
        print("  not OWA:      " + colors.dimmed(str(clean)))
        print("  unknown:      " + colors.warn(str(unknown)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} note(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  OWA hosts:"))
            for h in hits:
                line = "    " + colors.good(h.host)
                if h.version:
                    line += "  v" + h.version
                if h.frontend:
                    line += "  " + colors.dimmed("(fe=" + h.frontend + ")")
                print(line)

        return hits
