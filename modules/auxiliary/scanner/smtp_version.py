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
    (re.compile(r"Postfix", re.I), "Postfix"),
    (re.compile(r"Sendmail\s+([\d.]+)", re.I), "Sendmail"),
    (re.compile(r"Exim\s+([\d.]+)", re.I), "Exim"),
    (re.compile(r"Microsoft ESMTP MAIL Service.*Version:\s*([\d.]+)", re.I), "Microsoft Exchange"),
    (re.compile(r"Exchange", re.I), "Microsoft Exchange"),
    (re.compile(r"qmail", re.I), "qmail"),
    (re.compile(r"OpenSMTPD", re.I), "OpenSMTPD"),
    (re.compile(r"Haraka", re.I), "Haraka"),
    (re.compile(r"MailEnable", re.I), "MailEnable"),
    (re.compile(r"hMailServer", re.I), "hMailServer"),
    (re.compile(r"IceWarp", re.I), "IceWarp"),
    (re.compile(r"Kerio", re.I), "Kerio"),
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
    ehlo_ok: bool = False
    error: str = ""


class SMTPVersionScanner(Auxiliary):
    NAME = "SMTP Version Scanner"
    DESCRIPTION = (
        "Fingerprints SMTP servers by reading the 220 greeting banner and "
        "optionally probing EHLO. Extracts MTA software name and version "
        "from common fingerprints (Postfix, Sendmail, Exim, Exchange, etc.). "
        "No credentials required — the banner is sent immediately on connect."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "info"
    CHECK = True
    REFERENCES = [
        "https://www.ietf.org/rfc/rfc2821.txt",
        "https://www.infosecmatter.com/metasploit-module-library/?mm=auxiliary/scanner/smtp/smtp_version",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=25, type=int, description="SMTP port"),
        Option("TIMEOUT", default=5.0, type=float, description="per-host timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("EHLO", default=True, type=bool,
               description="send EHLO after banner to capture extensions"),
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

    def _probe(self, host):
        result = HostResult(host=host, port=self.options["RPORT"])
        timeout = self.options["TIMEOUT"]

        try:
            sock = socket.create_connection(
                (host, self.options["RPORT"]), timeout=timeout
            )
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

            banner_text, software, version = self._parse_banner(banner_raw)

            first = banner_text.split(maxsplit=1)[0] if banner_text else ""
            if not (first.isdigit() and len(first) == 3):
                result.error = "not SMTP (" + banner_text[:60] + ")"
                return result

            result.state = "up"
            result.banner = banner_text
            result.software = software
            result.version = version

            if self.options["EHLO"]:
                try:
                    sock.sendall(b"EHLO metis\r\n")
                    ehlo_resp = b""
                    for _ in range(20):
                        line = self._readline(sock, timeout)
                        if not line:
                            break
                        ehlo_resp += line
                        stripped = line.strip()
                        if stripped.startswith(b"250 ") and len(stripped) > 4:
                            break
                    if ehlo_resp.startswith(b"250"):
                        result.ehlo_ok = True
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
            name="smtp", banner=banner,
        )
        bits = ["banner=" + (h.banner or "(none)")]
        if h.software:
            bits.append("software=" + h.software)
        if h.version:
            bits.append("version=" + h.version)
        if h.ehlo_ok:
            bits.append("ehlo=ok")
        self.note(" ".join(bits), address=h.host, kind="smtp_info")

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
            line = "check: " + host + " -> SMTP"
            if r.software:
                line += " " + r.software
            if r.version:
                line += " " + r.version
            print(colors.good(line))
            print(colors.dimmed("  " + r.banner[:120]))
            return CheckResult.UNKNOWN
        if r.error:
            print(colors.safe("check: " + host + " not SMTP (" + r.error + ")"))
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
                        line += "  SMTP"
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
        print("  smtp:         " + colors.green(str(len(hits))))
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
            print(colors.heading("  smtp hosts:"))
            for h in hits:
                label = h.host + ":" + str(h.port)
                detail = ""
                if h.software:
                    detail = h.software
                    if h.version:
                        detail += " " + h.version
                else:
                    detail = "unknown MTA"
                print("    " + colors.good(label) + "  " + colors.session(detail))
                print("      " + colors.dimmed(h.banner[:100]))

        return hits
