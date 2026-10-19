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

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    version: str = ""
    router: str = ""

class NextjsDetect(Auxiliary):
    NAME = "Next.js Framework Detector"
    DESCRIPTION = (
        "Detects whether a web application is running Next.js and attempts "
        "to extract the version and router type (App Router vs Pages Router). "
        "Checks response headers, static asset paths, and the build manifest."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True
    REFERENCES = [
        "https://nextjs.org/docs",
        "https://github.com/vercel/next.js",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
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
                return r.status, r.read().decode(errors="replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace"), dict(e.headers)

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            st, body, headers = self._get(host, "/")
        except urllib.error.URLError as e:
            result.detail = type(e).__name__
            return result

        if st != 200:
            result.detail = "HTTP " + str(st)
            return result

        if headers.get("x-powered-by", "").lower() == "next.js":
            result.state = "confirmed"
            result.detail = "x-powered-by header"
        if "x-nextjs-cache" in headers:
            result.state = "confirmed"
            result.detail = "x-nextjs-cache header"
        if "x-nextjs-page" in headers:
            result.state = "confirmed"
            result.detail = "x-nextjs-page header"

        if result.state == "unknown":
            if "__NEXT_DATA__" in body:
                result.state = "confirmed"
                result.detail = "__NEXT_DATA__ script"
                result.router = "pages"
            elif "/_next/static/" in body:
                result.state = "confirmed"
                result.detail = "/_next/static/ assets"
            elif "self.__next_f" in body:
                result.state = "confirmed"
                result.detail = "RSC flight payload"
                result.router = "app"

        if result.state == "unknown":
            result.detail = "no Next.js indicators"
            return result

        version = self._extract_version(host, body)
        if version:
            result.version = version

        return result

    def _extract_version(self, host, body):
        m = re.search(r'__BUILD_MANIFEST="([^"]+)"', body)
        if not m:
            m = re.search(r'"buildId"\s*:\s*"([^"]+)"', body)
        if not m:
            return ""

        build_id = m.group(1)
        try:
            st, manifest, _ = self._get(host, "/_next/static/" + build_id + "/_buildManifest.js")
            if st == 200:
                vm = re.search(r'NEXT_VERSION="([\d.]+)"', manifest)
                if vm:
                    return vm.group(1)
        except urllib.error.URLError:
            pass

        return ""

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        banner = ""
        if h.version:
            banner = "Next.js " + h.version
        else:
            banner = "Next.js"
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name="http", banner=banner,
        )
        bits = ["detected=Next.js", "detail=" + h.detail]
        if h.version:
            bits.append("version=" + h.version)
        if h.router:
            bits.append("router=" + h.router)
        self.note(" ".join(bits), address=h.host, kind="nextjs_info")

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))
        r = self._probe(host)

        if r.state == "confirmed":
            line = "check: " + host + " is Next.js"
            if r.version:
                line += " v" + r.version
            if r.router:
                line += " (" + r.router + " router)"
            print(colors.good(line))
            return CheckResult.UNKNOWN

        if r.detail:
            print(colors.safe("check: " + host + " not Next.js (" + r.detail + ")"))
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
                        line = "[Next.js] " + r.host
                        if r.version:
                            line += " v" + r.version
                        if r.router:
                            line += " (" + r.router + ")"
                        line += " - " + r.detail
                        bar.log(colors.good(line))
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
        print("  nextjs:       " + colors.green(str(len(hits))))
        print("  not nextjs:   " + colors.dimmed(str(clean)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} note(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  next.js hosts:"))
            for h in hits:
                line = "    " + colors.good(h.host)
                if h.version:
                    line += "  v" + h.version
                if h.router:
                    line += "  " + colors.dimmed("(" + h.router + ")")
                print(line)

        return hits
