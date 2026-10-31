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

DRUPAL_PATHS = [
    "/",
    "/CHANGELOG.txt",
    "/core/install.php",
    "/user/login",
]

HEADER_PATTERNS = [
    re.compile(r"x-drupal", re.I),
    re.compile(r"x-generator:\s*drupal", re.I),
]

VERSION_PATTERN = re.compile(r'class="site-version">([0-9.x-]+)')
CHANGELOG_VERSION = re.compile(r"Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.I)


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    version: str = ""
    matched_path: str = ""


class DrupalDetect(Auxiliary):
    NAME = "Drupal Detection Scanner"
    DESCRIPTION = (
        "Detects Drupal installations and attempts to extract the version. "
        "Probes the site root, CHANGELOG.txt, /core/install.php, and "
        "/user/login. Confirms by matching X-Drupal or X-Generator headers, "
        "the content=\"Drupal meta tag, or the CHANGELOG.txt initial release "
        "signature. Detection only - no exploitation."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "info"
    CHECK = True
    REFERENCES = [
        "https://www.drupal.org/",
        "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/drupal-detect.yaml",
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
                headers = {k.lower(): v for k, v in r.headers.items()}
                body = r.read(200_000).decode(errors="replace")
                return r.status, headers, body
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            body = e.read(200_000).decode(errors="replace")
            return e.code, headers, body
        except urllib.error.URLError:
            raise

    def _header_match(self, headers):
        blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        for pat in HEADER_PATTERNS:
            if pat.search(blob):
                return True
        return False

    def _probe(self, host):
        result = HostResult(host=host)

        for path in DRUPAL_PATHS:
            try:
                st, headers, body = self._get(host, path)
            except urllib.error.URLError as e:
                result.detail = type(e).__name__
                return result

            if self._header_match(headers):
                result.state = "confirmed"
                result.matched_path = path
                result.detail = "header signature"
                result.version = self._extract_version(body)
                return result

            if 'content="Drupal' in body:
                result.state = "confirmed"
                result.matched_path = path
                result.detail = 'meta generator (content="Drupal")'
                result.version = self._extract_version(body)
                return result

            if "Initial release" in body and "Drupal 1.0.0" in body:
                result.state = "confirmed"
                result.matched_path = path
                result.detail = "CHANGELOG.txt"
                m = CHANGELOG_VERSION.search(body)
                if m:
                    result.version = m.group(1)
                return result

            if path == "/core/install.php":
                m = VERSION_PATTERN.search(body)
                if m:
                    result.version = m.group(1)

        result.state = "safe"
        result.detail = "no Drupal signature"
        return result

    def _extract_version(self, body):
        m = VERSION_PATTERN.search(body)
        if m:
            return m.group(1)
        m = re.search(r'content="Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', body, re.I)
        if m:
            return m.group(1)
        return ""

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        banner = "Drupal"
        if h.version:
            banner += " " + h.version
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner=banner,
        )
        bits = ["detected=Drupal", "path=" + h.matched_path]
        if h.version:
            bits.append("version=" + h.version)
        bits.append("detail=" + h.detail)
        self.note(" ".join(bits), address=h.host, kind="drupal_info")

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))

        r = self._probe(host)

        if r.state == "confirmed":
            line = "check: " + host + " is Drupal"
            if r.version:
                line += " v" + r.version
            line += " (" + r.detail + ")"
            print(colors.good(line))
            return CheckResult.UNKNOWN
        if r.state == "safe":
            print(colors.safe("check: " + host + " not Drupal (" + r.detail + ")"))
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
                        line = r.host
                        if r.version:
                            line += " v" + r.version
                        line += " (" + r.detail + ")"
                        bar.log(colors.good(line))
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
        print("  Drupal:       " + colors.green(str(len(hits))))
        print("  not Drupal:   " + colors.dimmed(str(clean)))
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
            print(colors.heading("  Drupal hosts:"))
            for h in hits:
                line = "    " + colors.good(h.host)
                if h.version:
                    line += "  v" + h.version
                line += "  " + colors.dimmed("(" + h.detail + ")")
                print(line)

        return hits
