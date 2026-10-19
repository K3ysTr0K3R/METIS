import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

MTA_PATTERNS = [
    (re.compile(r"Dovecot", re.I), "Dovecot"),
    (re.compile(r"Courier", re.I), "Courier"),
    (re.compile(r"UW(?:-IMAP)?", re.I), "UW-IMAP"),
    (re.compile(r"qpopper", re.I), "qpopper"),
    (re.compile(r"Microsoft.*POP3", re.I), "Microsoft Exchange POP3"),
    (re.compile(r"Exchange", re.I), "Microsoft Exchange POP3"),
    (re.compile(r"MailEnable", re.I), "MailEnable"),
    (re.compile(r"hMailServer", re.I), "hMailServer"),
    (re.compile(r"IceWarp", re.I), "IceWarp"),
    (re.compile(r"Kerio", re.I), "Kerio"),
    (re.compile(r"Citadel", re.I), "Citadel"),
    (re.compile(r"Zimbra", re.I), "Zimbra"),
    (re.compile(r"OpenPOP3", re.I), "OpenPOP3"),
]

VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


@dataclass
class HostResult:
    host: str
    port: int
    state: str = "down"
    banner: str = ""
    software: str = ""
    version: str = ""
    capa_ok: bool = False
    capa: list = None

    def __post_init__(self):
        if self.capa is None:
            self.capa = []


class POP3VersionScanner(Auxiliary):
    NAME = "POP3 Version Scanner"
    DESCRIPTION = (
        "Fingerprints POP3 servers by reading the +OK greeting banner and "
        "optionally issuing CAPA to enumerate extensions. Extracts server "
        "software and version from common fingerprints (Dovecot, Courier, "
        "UW-IMAP, Exchange, etc.). No credentials required."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True
    REFERENCES = [
        "https://www.ietf.org/rfc/rfc1939.txt",
        "https://www.ietf.org/rfc/rfc2449.txt",
        "https://www.infosecmatter.com/metasploit-module-library/?mm=auxiliary/scanner/pop3/pop3_version",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=110, type=int, description="POP3 port"),
        Option("SSL", default=False, type=bool, description="use POP3S (TLS)"),
        Option("TIMEOUT", default=5.0, type=float, description="per-host timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("CAPA", default=True, type=bool,
               description="send CAPA to enumerate extensions"),
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

    def _readline(self, sock, timeout):
        sock.settimeout(timeout)
        buf = b""
        while not buf.endswith(b"\r\n"):
            try:
                chunk = sock.recv(1)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 4096:
                break
        return buf

    def _parse_banner(self, line):
        text = line.decode("utf-8", errors="replace").strip()
        software = ""
        version = ""

        for pattern, name in MTA_PATTERNS:
            m = pattern.search(text)
            if m:
                software = name
                if m.groups():
                    version = m.group(1)
                break

        if not version:
            m = VERSION_RE.search(text)
            if m:
                version = m.group(1)

        return text, software, version

    def _connect(self, host):
        timeout = self.options["TIMEOUT"]
        if self.options["SSL"]:
            import ssl
            ctx = ssl._create_unverified_context()
            raw = socket.create_connection((host, self.options["RPORT"]), timeout=timeout)
            return ctx.wrap_socket(raw, server_hostname=host)
        return socket.create_connection((host, self.options["RPORT"]), timeout=timeout)

    def _read_capa(self, sock, timeout):
        sock.sendall(b"CAPA\r\n")
        lines = []
        while True:
            line = self._readline(sock, timeout)
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            lines.append(text)
            if text == ".":
                break
            if len(lines) > 100:
                break
        return lines

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
        except OSError as e:
            result.error = type(e).__name__
            return result

        try:
            banner_raw = self._readline(sock, timeout)
            if not banner_raw:
                result.error = "no banner"
                return result

            if not banner_raw.startswith(b"+OK"):
                text = banner_raw.decode("utf-8", errors="replace").strip()
                result.error = "not POP3 (" + text[:60] + ")"
                return result

            banner_text, software, version = self._parse_banner(banner_raw)
            result.state = "up"
            result.banner = banner_text
            result.software = software
            result.version = version

            if self.options["CAPA"]:
                try:
                    capa_lines = self._read_capa(sock, timeout)
                    if capa_lines and capa_lines[0].startswith("+OK"):
                        result.capa_ok = True
                        for line in capa_lines[1:]:
                            if line == ".":
                                break
                            result.capa.append(line)
                except socket.timeout:
                    pass

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

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        banner = h.banner[:200] if h.banner else ""
        self.report_service(
            h.host, h.port,
            proto="tcp", state="open",
            name="pop3", banner=banner,
        )
        bits = ["banner=" + (h.banner or "(none)")]
        if h.software:
            bits.append("software=" + h.software)
        if h.version:
            bits.append("version=" + h.version)
        if h.capa:
            bits.append("capa=" + ",".join(h.capa[:6]))
        self.note(" ".join(bits), address=h.host, kind="pop3_info")

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        print(colors.info("check: probing " + host + ":" + str(self.options["RPORT"])))

        r = self._probe(host)

        if r.state == "up":
            line = "check: " + host + " -> POP3"
            if r.software:
                line += " " + r.software
            if r.version:
                line += " " + r.version
            print(colors.good(line))
            print(colors.dimmed("  " + r.banner[:120]))
            if r.capa:
                print(colors.dimmed("  CAPA: " + ", ".join(r.capa[:8])))
            return CheckResult.UNKNOWN
        if getattr(r, "error", ""):
            print(colors.safe("check: " + host + " not POP3 (" + r.error + ")"))
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

                    if r.state == "up":
                        hits.append(r)
                        line = r.host + ":" + str(r.port)
                        line += "  POP3"
                        if r.software:
                            line += " " + r.software
                        if r.version:
                            line += " " + r.version
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
        print("  pop3:         " + colors.green(str(len(hits))))
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
            print(colors.heading("  pop3 hosts:"))
            for h in hits:
                label = h.host + ":" + str(h.port)
                detail = ""
                if h.software:
                    detail = h.software
                    if h.version:
                        detail += " " + h.version
                else:
                    detail = "unknown"
                print("    " + colors.good(label) + "  " + colors.session(detail))
                print("      " + colors.dimmed(h.banner[:100]))
                if h.capa:
                    print("      " + colors.dimmed("CAPA: " + ", ".join(h.capa[:6])))

        return hits
