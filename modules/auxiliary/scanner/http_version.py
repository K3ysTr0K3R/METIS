import socket
import ssl
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
    port: int
    state: str = "down"
    status_line: str = ""
    server: str = ""
    powered_by: str = ""
    error: str = ""


class HTTPVersionScanner(Auxiliary):
    NAME = "HTTP Version Scanner"
    DESCRIPTION = (
        "Fingerprints HTTP servers by sending a HEAD request and reporting "
        "the Server header verbatim, plus X-Powered-By when present. "
        "Supports HTTP and HTTPS. No credentials required."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "info"
    CHECK = True
    REFERENCES = [
        "https://www.ietf.org/rfc/rfc2616.txt",
        "https://nmap.org/nsedoc/scripts/http-server-header.html",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("PATH", default="/", description="request path"),
        Option("TIMEOUT", default=5.0, type=float, description="per-host timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first responding host"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _connect(self, host):
        timeout = self.options["TIMEOUT"]
        sock = socket.create_connection((host, self.options["RPORT"]), timeout=timeout)
        if self.options["SSL"]:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        return sock

    def _build_request(self, host):
        path = self.options["PATH"] or "/"
        if not path.startswith("/"):
            path = "/" + path
        host_header = host
        default_port = 443 if self.options["SSL"] else 80
        if self.options["RPORT"] != default_port:
            host_header += ":" + str(self.options["RPORT"])
        return (
            "HEAD " + path + " HTTP/1.0\r\n"
            "Host: " + host_header + "\r\n"
            "User-Agent: Mozilla/5.0 (metis)\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()

    def _read_headers(self, sock, timeout):
        sock.settimeout(timeout)
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        return buf

    def _parse_headers(self, response):
        text = response.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        status_line = lines[0] if lines else ""
        server = ""
        powered_by = ""

        for line in lines[1:]:
            if not line:
                break
            name, _, value = line.partition(":")
            name = name.strip().lower()
            value = value.strip()
            if name == "server":
                server = value
            elif name == "x-powered-by":
                powered_by = value

        return status_line, server, powered_by

    def _probe(self, host):
        result = HostResult(host=host, port=self.options["RPORT"])
        timeout = self.options["TIMEOUT"]

        try:
            sock = self._connect(host)
        except socket.timeout:
            result.error = "timeout"
            return result
        except ConnectionRefusedError:
            result.error = "connection refused"
            return result
        except ssl.SSLError as e:
            result.error = "ssl: " + type(e).__name__
            return result
        except OSError as e:
            result.error = type(e).__name__
            return result

        try:
            sock.sendall(self._build_request(host))
            response = self._read_headers(sock, timeout)

            if not response:
                result.error = "no response"
                return result
            if not response.startswith(b"HTTP/"):
                result.error = "not HTTP"
                return result

            status_line, server, powered_by = self._parse_headers(response)
            result.state = "up"
            result.status_line = status_line
            result.server = server
            result.powered_by = powered_by

        except socket.timeout:
            result.error = "read timeout"
        except OSError as e:
            result.error = type(e).__name__
        finally:
            try:
                sock.close()
            except OSError:
                pass

        return result

    def _record_host_result(self, h, svc_name):
        self.report_host(h.host, state="up")

        self.report_service(
            h.host, h.port,
            proto="tcp", state="open",
            name=svc_name, banner=h.server or "",
        )

        bits = []
        if h.status_line:
            bits.append("status=" + h.status_line)
        bits.append("server=" + (h.server or "(hidden)"))
        if h.powered_by:
            bits.append("x-powered-by=" + h.powered_by)
        self.note(
            " ".join(bits),
            address=h.host,
            kind="http_version",
        )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        scheme = "https" if self.options["SSL"] else "http"
        print(colors.info("check: probing " + scheme + "://" + host + ":" + str(self.options["RPORT"])))

        r = self._probe(host)

        if r.state == "up":
            print(colors.good("check: " + host + " -> HTTP"))
            if r.status_line:
                print(colors.dimmed("  " + r.status_line))
            print(colors.dimmed("  Server: " + (r.server or "(hidden)")))
            if r.powered_by:
                print(colors.dimmed("  X-Powered-By: " + r.powered_by))
            return CheckResult.UNKNOWN
        if r.error:
            print(colors.safe("check: " + host + " not HTTP (" + r.error + ")"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info("scanning " + str(len(targets)) + " host(s) with "
                          + str(threads) + " threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits = []
        clean = 0
        aborted = False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())
        svc_name = "https" if self.options["SSL"] else "http"

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

                    if r.state != "up":
                        clean += 1
                        continue

                    hits.append(r)
                    bar.log(colors.good(
                        r.host + ":" + str(r.port) + "  "
                        + (r.server or "(no Server header)")
                    ))

                    if workspace_active:
                        self._record_host_result(r, svc_name)

                    if stop_first:
                        aborted = True
                        for f in futures:
                            f.cancel()
                        break
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  http:         " + colors.green(str(len(hits))))
        print("  no response:  " + colors.dimmed(str(clean)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} note(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  http hosts:"))
            for h in hits:
                print("    " + colors.good(h.host + ":" + str(h.port)))
                print("      " + colors.session("Server: " + (h.server or "(hidden)")))
                if h.powered_by:
                    print("      " + colors.session("X-Powered-By: " + h.powered_by))

        return hits
