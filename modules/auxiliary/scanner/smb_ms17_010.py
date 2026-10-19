import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

STATUS_SUCCESS                 = 0x00000000
STATUS_INVALID_HANDLE          = 0xC0000008
STATUS_ACCESS_DENIED           = 0xC0000022
STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205

@dataclass
class HostResult:
    host: str
    port: int
    state: str = "down"
    vulnerable: str = "unknown"
    status_code: int = 0
    status_name: str = ""
    error: str = ""


class MS17_010Scanner(Auxiliary):
    NAME = "MS17-010 EternalBlue Scanner"
    DESCRIPTION = (
        "Detects MS17-010 (EternalBlue) by negotiating SMB1 via impacket's "
        "smb.SMB class, connecting to IPC$, and issuing a TRANS_PEEK_NMPIPE "
        "transaction on FID 0. Unpatched hosts return "
        "STATUS_INSUFF_SERVER_RESOURCES; patched hosts return "
        "STATUS_ACCESS_DENIED or STATUS_INVALID_HANDLE."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True
    REFERENCES = [
        "https://technet.microsoft.com/en-us/library/security/ms17-010.aspx",
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_ms17_010.rb",
        "https://github.com/worawit/MS17-010",
        "https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=445, type=int, description="SMB port (445)"),
        Option("TIMEOUT", default=5.0, type=float, description="per-host timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first vulnerable host"),
        Option("VERBOSE", default=False, type=bool,
               description="log per-host errors (timeouts, refused, IPC$ denied) during scan"),
    ]

    def __init__(self):
        super().__init__()
        try:
            from impacket import smb  # noqa: F401
            self._have_impacket = True
        except ImportError:
            self._have_impacket = False

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _classify_status(self, status):
        if status == STATUS_INSUFF_SERVER_RESOURCES:
            return "yes", "STATUS_INSUFF_SERVER_RESOURCES"
        if status == STATUS_ACCESS_DENIED:
            return "no", "STATUS_ACCESS_DENIED"
        if status == STATUS_INVALID_HANDLE:
            return "no", "STATUS_INVALID_HANDLE"
        if status == STATUS_SUCCESS:
            return "no", "STATUS_SUCCESS"
        return "unknown", "0x{:08x}".format(status & 0xFFFFFFFF)

    def _probe(self, host):
        from impacket import smb

        result = HostResult(host=host, port=self.options["RPORT"])
        conn = None

        try:
            conn = smb.SMB(
                "*SMBSERVER",
                host,
                sess_port=self.options["RPORT"],
                timeout=self.options["TIMEOUT"],
            )
        except socket.timeout:
            result.error = "negotiate timeout"
            return result
        except ConnectionRefusedError:
            result.error = "connection refused"
            return result
        except Exception as e:
            result.error = "negotiate: {}: {}".format(
                type(e).__name__, str(e)[:100]
            )
            return result

        try:
            try:
                conn.login("", "")
            except Exception:
                pass

            try:
                tid = conn.tree_connect_andx("\\\\" + host + "\\IPC$")
            except Exception as e:
                result.error = "IPC$: {}: {}".format(
                    type(e).__name__, str(e)[:100]
                )
                result.state = "up"
                return result

            try:
                params = smb.SMBTransaction_Parameters()
                params['TotalParameterCount'] = 0
                params['TotalDataCount']       = 0
                params['MaxParameterCount']    = 0xFFFF
                params['MaxDataCount']         = 0xFFFF
                params['MaxSetupCount']        = 0
                params['Flags']                = 0
                params['Timeout']              = 0xFFFFFFFF
                params['ParameterCount']       = 0
                params['ParameterOffset']      = 0x4A
                params['DataCount']            = 0
                params['DataOffset']           = 0x4A
                params['SetupCount']           = 1
                params['Setup']                = b"\x23\x00"
                params['Reserved1']            = 0
                params['Reserved2']            = 0
                params['Reserved3']            = 0

                cmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION)
                cmd['Parameters'] = params
                cmd['Data']       = b"\\PIPE\\"

                pkt = smb.NewSMBPacket()
                pkt['Tid']      = tid
                pkt['Pid']      = 0xFEFF
                pkt['Uid']      = conn.get_uid()
                pkt['Mid']      = 0
                pkt['Flags1']   = 0x18
                pkt['Flags2']   = 0x2801

                pkt.addCommand(cmd)

                conn.sendSMB(pkt)
                resp = conn.recvSMB()

                status = 0
                try:
                    status = resp['ErrorCode']
                except Exception:
                    try:
                        raw = resp.getData()
                        if len(raw) >= 13:
                            status = struct.unpack_from("<I", raw, 9)[0]
                    except Exception:
                        status = 0

                result.status_code = status
                verdict, sname = self._classify_status(status)
                result.vulnerable = verdict
                result.status_name = sname
                result.state = "up"

            except socket.timeout:
                result.error = "transaction timeout"
                result.state = "up"
                return result
            except Exception as e:
                result.error = "transaction: {}: {}".format(
                    type(e).__name__, str(e)[:100]
                )
                result.state = "up"
                return result

        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

        return result

    def _print_result(self, r):
        if r.state != "up":
            print(colors.dimmed("  " + r.host + ": " + (r.error or "unreachable")))
            return

        line = colors.info(r.host + ":" + str(r.port))

        if r.vulnerable == "yes":
            line += "  " + colors.bad("VULNERABLE to MS17-010")
            line += "  " + colors.dimmed("(" + r.status_name + ")")
        elif r.vulnerable == "no":
            line += "  " + colors.good("patched")
            line += "  " + colors.dimmed("(" + r.status_name + ")")
        else:
            line += "  " + colors.warn("unknown")
            if r.status_name:
                line += "  " + colors.dimmed("(" + r.status_name + ")")
            if r.error:
                line += "  " + colors.dimmed("[" + r.error + "]")

        print(line)

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, h.port,
            proto="tcp", state="open",
            name="microsoft-ds", banner="",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="MS17-010",
            info=h.status_name,
        )

    def check(self):
        if not self._have_impacket:
            print(colors.bad("impacket is required: pip install impacket"))
            return CheckResult.UNKNOWN

        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + host + ":" + str(self.options["RPORT"])))

        r = self._probe(host)
        self._print_result(r)

        if r.vulnerable == "yes":
            return CheckResult.VULNERABLE
        if r.vulnerable == "no":
            return CheckResult.SAFE
        return CheckResult.UNKNOWN

    def action(self):
        if not self._have_impacket:
            print(colors.bad("impacket is required: pip install impacket"))
            return []

        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info(
            "scanning " + str(len(targets)) + " host(s) with "
            + str(threads) + " threads"
        ))

        bar = ProgressBar(total=len(targets), prefix="scan")
        vuln = []
        patched = 0
        unknown = 0
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
                        if r.vulnerable == "yes":
                            vuln.append(r)
                            bar.log(colors.bad(r.host + "  VULNERABLE to MS17-010"))
                            if workspace_active:
                                self._record_host_result(r)
                            if stop_first:
                                aborted = True
                                for f in futures:
                                    f.cancel()
                                break
                        elif r.vulnerable == "no":
                            patched += 1
                            bar.log(colors.good(r.host + "  patched"))
                        else:
                            unknown += 1
                            detail = r.status_name or r.error or "no status"
                            bar.log(colors.warn(r.host + "  unknown (" + detail + ")"))
                    else:
                        clean += 1
                        if self.options["VERBOSE"] and r.error:
                            bar.log(colors.dimmed(r.host + ": " + r.error))
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  vulnerable:   " + colors.bad(str(len(vuln))))
        print("  patched:      " + colors.good(str(patched)))
        print("  unknown:      " + colors.warn(str(unknown)))
        print("  no response:  " + colors.dimmed(str(clean)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and vuln:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(vuln)} host(s), {len(vuln)} service(s), "
                f"{len(vuln)} vuln(s) in workspace '{ws}'"
            ))

        if vuln:
            print(colors.heading("  vulnerable hosts:"))
            for h in vuln:
                line = "    " + colors.bad(h.host + ":" + str(h.port))
                line += "  " + colors.dimmed("(" + h.status_name + ")")
                print(line)

        return vuln
