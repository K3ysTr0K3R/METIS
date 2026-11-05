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

LOGIN_PATH = "/login"
TITLE_RE = re.compile(r"<title>\s*Login\s*-\s*ESPHome\s*</title>", re.I)
BODY_MARKER = 'class="esphome-header"'


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    matched_path: str = ""
    version: str = ""


class ESPHomeDetect(Auxiliary):
    NAME = "ESPHome Instance Detection Scanner"
    DESCRIPTION = (
        "Detects ESPHome web_server instances by probing /login and "
        "matching the page title 'Login - ESPHome' and the "
        "class=\"esphome-header\" body marker. Both must be present for "
        "confirmation. Detection only - no auth attempts, no exploitation."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "info"
    CHECK = True
    REFERENCES = [
        "https://esphome.io/components/web_server/",
        "https://github.com/runZeroInc/nuclei-templates/blob/main/http/exposed-panels/esphome-panel.yaml",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
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
                return r.status, r.read(200_000).decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(200_000).decode(errors="replace")
        except urllib.error.URLError:
            raise

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            st, body = self._get(host, LOGIN_PATH)
        except urllib.error.URLError as e:
            result.detail = type(e).__name__
            return result

        if st not in (200, 401):
            result.state = "safe"
            result.detail = "/login returned HTTP " + str(st)
            return result

        title_match = bool(TITLE_RE.search(body))
        body_match = BODY_MARKER in body

        if title_match and body_match:
            result.state = "confirmed"
            result.matched_path = LOGIN_PATH
            m = re.search(r"(\d{4}\.\d+\.\d+)\s+Documentation", body)
            if m:
                result.version = m.group(1)
            detail = "ESPHome detected (title + header class)"
            if result.version:
                detail += " v" + result.version
            result.detail = detail
            return result

        if title_match or body_match:
            result.state = "unknown"
            partial = []
            if title_match:
                partial.append("title")
            if body_match:
                partial.append("header class")
            result.detail = "partial markers only (" + " + ".join(partial) + ")"
            return result

        result.state = "safe"
        result.detail = "no ESPHome markers on /login"
        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        banner = "ESPHome"
        if h.version:
            banner += " " + h.version
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner=banner,
        )
        bits = ["detected=ESPHome", "path=" + h.matched_path]
        if h.version:
            bits.append("version=" + h.version)
        self.note(" ".join(bits), address=h.host, kind="esphome_info")

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

        if r.state == "confirmed":
            print(colors.good("check: " + host + " - " + r.detail))
            return CheckResult.UNKNOWN
        if r.state == "safe":
            print(colors.safe("check: " + host + " not ESPHome (" + r.detail + ")"))
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
        print("  ESPHome:      " + colors.green(str(len(hits))))
        print("  not ESPHome:  " + colors.dimmed(str(clean)))
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
            print(colors.heading("  ESPHome hosts:"))
            for h in hits:
                line = "    " + colors.good(h.host)
                if h.version:
                    line += "  v" + h.version
                line += "  " + colors.dimmed("(" + h.detail + ")")
                print(line)

        return hits
