import socket
import struct
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
    protocol: int = 0
    version: str = ""
    error: str = ""


class MySQLVersionScanner(Auxiliary):
    NAME = "MySQL Version Scanner"
    DESCRIPTION = (
        "Fingerprints MySQL/MariaDB servers by reading the initial "
        "HandshakeV10 packet. No credentials required — MySQL sends the "
        "server version immediately after the TCP connection is established."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True
    REFERENCES = [
        "https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html",
        "https://docs.metasploit.com/docs/pentesting/metasploit-guide-mysql.html",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=3306, type=int, description="MySQL port"),
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

    def _probe(self, host):
        result = HostResult(host=host, port=self.options["RPORT"])
        timeout = self.options["TIMEOUT"]

        try:
            sock = socket.create_connection((host, self.options["RPORT"]), timeout=timeout)
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
            sock.settimeout(timeout)
            header = sock.recv(4)
            if len(header) < 4:
                result.error = "short header"
                return result

            l0, l1, l2, seq = struct.unpack("BBBB", header)
            length = l0 | (l1 << 8) | (l2 << 16)

            # Read payload
            payload = b""
            remaining = length
            while remaining > 0:
                chunk = sock.recv(remaining)
                if not chunk:
                    break
                payload += chunk
                remaining -= len(chunk)

            if not payload:
                result.error = "empty payload"
                return result

            proto = payload[0]
            if proto == 0xFF:
                result.state = "up"
                result.error = "server error response"
                return result

            nul = payload.find(b"\x00", 1)
            if nul == -1:
                result.error = "unterminated version"
                return result

            version = payload[1:nul].decode("utf-8", errors="replace").strip()
            result.state = "up"
            result.protocol = proto
            result.version = version
            return result

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

        if r.state == "up" and r.version:
            print(colors.good("check: " + host + " -> MySQL " + r.version
                              + " (protocol " + str(r.protocol) + ")"))
            return CheckResult.UNKNOWN
        if r.error:
            print(colors.safe("check: " + host + " not MySQL (" + r.error + ")"))
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

                    if r.state == "up" and r.version:
                        hits.append(r)
                        line = r.host + ":" + str(r.port)
                        line += "  MySQL " + r.version
                        line += "  (protocol " + str(r.protocol) + ")"
                        bar.log(colors.good(line))
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
        print("  mysql:        " + colors.green(str(len(hits))))
        print("  no response:  " + colors.dimmed(str(clean)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if hits:
            print(colors.heading("  mysql hosts:"))
            for h in hits:
                print("    " + colors.good(h.host + ":" + str(h.port))
                      + "  " + colors.session(h.version))

        return hits
