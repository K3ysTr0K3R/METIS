import base64
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

DEFAULT_PATHS = ",".join([
    "/", "/live.sdp", "/live", "/stream1", "/stream", "/h264", "/h264.sdp",
    "/11", "/12", "/ch0", "/ch0_0.h264", "/ch01.264",
    "/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1",
    "/Streaming/Channels/101", "/Streaming/Channels/1", "/onvif1", "/onvif2",
    "/video1", "/video", "/mpeg4", "/media/video1", "/axis-media/media.amp",
    "/videoMain", "/videostream.asf", "/img/video.sav",
])

SDP_TITLE_RE = re.compile(r"^s=(.*)$", re.MULTILINE)


@dataclass
class PathHit:
    path: str
    status_code: int
    reason: str = ""
    content_type: str | None = None
    sdp_title: str | None = None
    auth_bypassed_with: str | None = None


@dataclass
class HostResult:
    host: str
    port: int
    banner: str | None = None
    methods: list[str] = field(default_factory=list)
    hits: list[PathHit] = field(default_factory=list)
    auth_only_paths: list[str] = field(default_factory=list)
    error: str | None = None


class RTSPScanner(Auxiliary):
    NAME = "RTSP Detection Scanner"
    DESCRIPTION = (
        "Detects RTSP services and probes common stream paths for "
        "unauthenticated access. Optionally tries a small credential list "
        "via RTSP Basic auth against paths that return 401. Supports "
        "single hosts, comma lists, CIDR, ranges, and file: target specs."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=554, type=int, description="RTSP port"),
        Option("PATHS", default=DEFAULT_PATHS,
               description="comma-separated stream paths to probe with DESCRIBE"),
        Option("CREDENTIALS", default="",
               description="comma list of user:pass pairs to try via Basic auth on 401 paths (optional)"),
        Option("TIMEOUT", default=5.0, type=float, description="per-connection timeout"),
        Option("THREADS", default=10, type=int, description="concurrent workers (host scan)"),
        Option("PATH_THREADS", default=5, type=int,
               description="concurrent workers per host (path scan)"),
        Option("FIND_ALL", default=True, type=bool,
               description="keep scanning after first open stream (off = stop at first per host)"),
        Option("USER_AGENT", default="METIS rtsp-scanner",
               description="User-Agent header sent with each RTSP request"),
    ]

    def _rtsp_url(self, host, path=""):
        if not path.startswith("/"):
            path = "/" + path
        return f"rtsp://{host}:{self.options['RPORT']}{path}"

    @staticmethod
    def _recv_head(sock, timeout):
        sock.settimeout(timeout)
        marker = b"\r\n\r\n"
        buf = b""
        while marker not in buf and len(buf) < 65536:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        if marker not in buf:
            return b"", b""
        head, _, rest = buf.partition(marker)
        return head, rest

    @staticmethod
    def _parse_head(head: bytes):
        text = head.decode("latin-1", errors="replace")
        lines = text.split("\r\n")
        m = re.match(r"RTSP/\d\.\d\s+(\d{3})\s*(.*)", lines[0]) if lines else None
        if not m:
            return None, "", {}
        code = int(m.group(1))
        reason = m.group(2).strip()
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().title()] = v.strip()
        return code, reason, headers

    @staticmethod
    def _read_body(sock, rest, length, timeout):
        body = rest
        remaining = length - len(body)
        sock.settimeout(timeout)
        while remaining > 0:
            try:
                chunk = sock.recv(min(4096, remaining))
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
            remaining -= len(chunk)
        return body

    def _transact(self, host, method, path, extra_headers=None):
        timeout = self.options["TIMEOUT"]
        url = self._rtsp_url(host, path)
        lines = [f"{method} {url} RTSP/1.0", "CSeq: 1",
                 f"User-Agent: {self.options['USER_AGENT']}"]
        if extra_headers:
            lines.extend(f"{k}: {v}" for k, v in extra_headers.items())
        request = ("\r\n".join(lines) + "\r\n\r\n").encode()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((host, self.options["RPORT"]))
            sock.sendall(request)
            head, rest = self._recv_head(sock, timeout)
            if not head:
                return None
            code, reason, headers = self._parse_head(head)
            if code is None:
                return None
            body = b""
            length = int(headers.get("Content-Length", 0) or 0)
            if length:
                body = self._read_body(sock, rest, length, timeout)
            return {"code": code, "reason": reason, "headers": headers, "body": body}
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    def _expand_targets(self) -> list[str]:
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info(f"target list -> {len(hosts)} hosts"))
        return hosts

    def _get_paths(self) -> list[str]:
        paths = self.options["PATHS"] or "/"
        return [p.strip() for p in paths.split(",") if p.strip()]

    def _get_credentials(self) -> list[tuple[str, str]]:
        raw = self.options["CREDENTIALS"] or ""
        pairs = []
        for item in raw.split(","):
            item = item.strip()
            if not item or ":" not in item:
                continue
            user, _, pw = item.partition(":")
            pairs.append((user, pw))
        return pairs

    def _basic_auth_header(self, user: str, pw: str) -> str:
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        return f"Basic {token}"

    def _check_path(self, host: str, path: str, creds: list[tuple[str, str]]):
        resp = self._transact(host, "DESCRIBE", path)
        if resp is None:
            return None, False

        if resp["code"] == 200:
            body = resp["body"].decode("latin-1", errors="replace")
            title_m = SDP_TITLE_RE.search(body)
            sdp_title = title_m.group(1).strip()[:80] if title_m else None
            return PathHit(
                path=path, status_code=200, reason=resp["reason"],
                content_type=resp["headers"].get("Content-Type"),
                sdp_title=sdp_title,
            ), False

        if resp["code"] == 401:
            for user, pw in creds:
                auth_resp = self._transact(
                    host, "DESCRIBE", path,
                    extra_headers={"Authorization": self._basic_auth_header(user, pw)},
                )
                if auth_resp and auth_resp["code"] == 200:
                    body = auth_resp["body"].decode("latin-1", errors="replace")
                    title_m = SDP_TITLE_RE.search(body)
                    sdp_title = title_m.group(1).strip()[:80] if title_m else None
                    return PathHit(
                        path=path, status_code=200, reason=auth_resp["reason"],
                        content_type=auth_resp["headers"].get("Content-Type"),
                        sdp_title=sdp_title, auth_bypassed_with=f"{user}:{pw}",
                    ), False
            return None, True

        return None, False

    def _probe(self, host: str) -> HostResult:
        port = self.options["RPORT"]
        res = HostResult(host=host, port=port)

        opts_resp = self._transact(host, "OPTIONS", "/")
        if opts_resp is None:
            res.error = "no RTSP response"
            return res

        res.banner = opts_resp["headers"].get("Server")
        res.methods = [m.strip() for m in opts_resp["headers"].get("Public", "").split(",") if m.strip()]

        creds = self._get_credentials()
        paths = self._get_paths()
        find_all = self.options["FIND_ALL"]
        path_workers = max(1, self.options["PATH_THREADS"])

        try:
            with ThreadPoolExecutor(max_workers=path_workers) as ex:
                futures = {ex.submit(self._check_path, host, p, creds): p for p in paths}
                for fut in as_completed(futures):
                    hit, needs_auth = fut.result()
                    if hit:
                        res.hits.append(hit)
                        if not find_all:
                            for f in futures:
                                f.cancel()
                            break
                    elif needs_auth:
                        res.auth_only_paths.append(futures[fut])
        except Exception as e:
            res.error = type(e).__name__

        res.hits.sort(key=lambda h: h.path)
        res.auth_only_paths.sort()
        return res

    def _format_hit(self, host: str, hit: PathHit) -> str:
        url = self._rtsp_url(host, hit.path)
        label = f"{url}"
        if hit.sdp_title:
            label += f' "{hit.sdp_title}"'
        if hit.auth_bypassed_with:
            label += f" (cracked: {hit.auth_bypassed_with})"
        return label

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, h.port,
            proto="tcp", state="open",
            name="rtsp", banner=(h.banner or "")[:200],
        )
        for hit in h.hits:
            note = "rtsp_stream=" + self._rtsp_url(h.host, hit.path)
            if hit.sdp_title:
                note += ' "' + hit.sdp_title + '"'
            if hit.content_type:
                note += " ctype=" + hit.content_type
            if hit.auth_bypassed_with:
                note += " auth=" + hit.auth_bypassed_with
            self.note(note, address=h.host, kind="rtsp_stream")
            if hit.auth_bypassed_with:
                user, _, pw = hit.auth_bypassed_with.partition(":")
                self.report_cred(
                    h.host, user, pw,
                    kind="password",
                    info="RTSP Basic auth on " + self._rtsp_url(h.host, hit.path),
                )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                f"check on multiple targets: probing only {targets[0]} "
                f"(use 'run' to scan all {len(targets)})"
            ))
        host = targets[0]
        print(colors.info(f"check: probing {host}:{self.options['RPORT']}"))
        res = self._probe(host)

        if res.error:
            print(colors.safe(f"check: {host} — {res.error}"))
            return CheckResult.SAFE

        if res.banner:
            print(colors.info(f"check: RTSP banner — {res.banner}"))
        if res.methods:
            print(colors.dimmed(f"check: supported methods — {', '.join(res.methods)}"))

        if res.hits:
            for hit in res.hits:
                print(colors.vuln(f"check: {self._format_hit(host, hit)}"))
            return CheckResult.VULNERABLE

        if res.auth_only_paths:
            print(colors.safe(
                f"check: {len(res.auth_only_paths)} path(s) require auth, "
                f"none accessible with provided CREDENTIALS"
            ))
        else:
            print(colors.safe("check: RTSP service found but no accessible streams"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])

        print(colors.info(f"scanning {len(targets)} host(s) with {threads} threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits, protected, errors = [], 0, 0

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._probe, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        res = fut.result()
                    except Exception:
                        errors += 1
                        continue
                    if res.error:
                        errors += 1
                        continue
                    if res.hits:
                        hits.append(res)
                        for hit in res.hits:
                            bar.log(colors.vuln(f"{res.host}: {self._format_hit(res.host, hit)}"))
                        if workspace_active:
                            self._record_host_result(res)
                    elif res.auth_only_paths:
                        protected += 1
        finally:
            bar.done()

        total_hits = sum(len(h.hits) for h in hits)
        print()
        print(colors.heading("--- scan summary ---"))
        print(f"  targets:          {len(targets)}")
        print(f"  open streams on:  {colors.green(str(len(hits)))} host(s)")
        print(f"  streams found:    {colors.green(str(total_hits))}")
        print(f"  auth-only hosts:  {colors.dimmed(str(protected))}")
        print(f"  errors/no-rtsp:   {colors.dimmed(str(errors))}")
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:         " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{total_hits} note(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  open streams:"))
            for h in hits:
                banner = f" ({h.banner})" if h.banner else ""
                for hit in h.hits:
                    print(f"    {colors.vuln(h.host)}{banner}: {self._format_hit(h.host, hit)}")
        return hits
