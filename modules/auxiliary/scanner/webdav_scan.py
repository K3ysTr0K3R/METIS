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


DANGEROUS_METHODS = {"PUT", "DELETE", "MKCOL", "COPY", "MOVE", "PROPFIND", "PROPPATCH", "LOCK", "UNLOCK"}


@dataclass
class HostResult:
    host: str
    url: str
    enabled: bool = False
    methods: list = field(default_factory=list)
    dangerous: list = field(default_factory=list)
    status: int = 0
    error: str | None = None


class WebDAVScanner(Auxiliary):
    NAME = "WebDAV Scanner"
    DESCRIPTION = (
        "Checks whether WebDAV is enabled on a target by sending an OPTIONS "
        "request and inspecting the Allow and DAV response headers. Flags "
        "dangerous methods such as PUT, DELETE, MOVE, and COPY. Optionally "
        "probes for the WebDAV root path."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True
    REFERENCES = [
        "https://datatracker.ietf.org/doc/html/rfc4918",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("PATH", default="/", description="URL path to test"),
        Option("TIMEOUT", default=5.0, type=float, description="per-request timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first WebDAV-enabled host"),
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

    def _probe(self, host):
        base = self._base_url(host)
        path = self.options["PATH"]
        if not path.startswith("/"):
            path = "/" + path
        url = base + path

        result = HostResult(host=host, url=url)

        try:
            r = requests.request(
                "OPTIONS",
                url,
                timeout=self.options["TIMEOUT"],
                verify=False,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            result.error = type(e).__name__
            return result

        result.status = r.status_code

        if r.status_code >= 400:
            result.error = "HTTP " + str(r.status_code)
            return result

        allow = r.headers.get("Allow", "")
        dav = r.headers.get("DAV", "")

        if allow:
            methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
            result.methods = methods

        if not dav:
            result.error = "no DAV header"
            return result

        result.enabled = True
        result.dangerous = sorted(set(result.methods) & DANGEROUS_METHODS)
        return result

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host) + self.options["PATH"]))
        r = self._probe(host)

        if r.enabled:
            print(colors.vuln("check: " + host + " has WebDAV enabled"))
            print(colors.dimmed("  Allow: " + ", ".join(r.methods)))
            if r.dangerous:
                print(colors.warn("  dangerous: " + ", ".join(r.dangerous)))
            return CheckResult.VULNERABLE

        if r.error:
            print(colors.safe("check: " + host + " - " + r.error))
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

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._probe, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        r = fut.result()
                    except Exception:
                        errors += 1
                        continue

                    if r.enabled:
                        hits.append(r)
                        line = r.host + " - WebDAV enabled"
                        if r.dangerous:
                            line += "  [dangerous: " + ", ".join(r.dangerous) + "]"
                        bar.log(colors.vuln(line))
                        if stop_first:
                            aborted = True
                            for f in futures:
                                f.cancel()
                            break
                    elif r.error:
                        errors += 1
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  webdav:       " + colors.green(str(len(hits))))
        print("  errors/skips: " + colors.dimmed(str(errors)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if hits:
            print(colors.heading("  webdav-enabled hosts:"))
            for h in hits:
                line = "    " + colors.vuln(h.host)
                if h.dangerous:
                    line += "  " + colors.warn("(" + ", ".join(h.dangerous) + ")")
                print(line)

        return hits