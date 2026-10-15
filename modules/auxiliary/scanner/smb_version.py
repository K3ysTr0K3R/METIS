import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

try:
    from impacket.smbconnection import SMBConnection, SMB_DIALECT
    from impacket.smb3structs import (
        SMB2_DIALECT_002,
        SMB2_DIALECT_21,
        SMB2_DIALECT_30,
        SMB2_DIALECT_302,
        SMB2_DIALECT_311,
        SMB2_DIALECT_WILDCARD,
        SMB2_ENCRYPTION_CAPABILITIES,
        SMB2_COMPRESSION_CAPABILITIES,
        SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
    )
    
except ImportError:
    SMB2_DIALECT_002 = 0x0202
    SMB2_DIALECT_21 = 0x0210
    SMB2_DIALECT_30 = 0x0300
    SMB2_DIALECT_302 = 0x0302
    SMB2_DIALECT_311 = 0x0311
    SMB2_DIALECT_WILDCARD = 0x02FF
    SMB2_ENCRYPTION_CAPABILITIES = 0x0002
    SMB2_COMPRESSION_CAPABILITIES = 0x0003
    SMB2_PREAUTH_INTEGRITY_CAPABILITIES = 0x0001


DIALECT_MAP = {
    SMB2_DIALECT_002: "SMB 2.0.2",
    SMB2_DIALECT_21: "SMB 2.1",
    SMB2_DIALECT_30: "SMB 3.0",
    SMB2_DIALECT_302: "SMB 3.0.2",
    SMB2_DIALECT_311: "SMB 3.1.1",
    SMB2_DIALECT_WILDCARD: "SMB 2.???",
}

ENCRYPTION_ALGO_MAP = {
    0x0001: "AES-128-CCM",
    0x0002: "AES-128-GCM",
    0x0003: "AES-256-CCM",
    0x0004: "AES-256-GCM",
}

COMPRESSION_ALGO_MAP = {
    0x0000: "NONE",
    0x0001: "LZNT1",
    0x0002: "LZ77",
    0x0003: "LZ77+Huffman",
    0x0004: "Pattern_V1",
    0x0005: "LZ4",
}

@dataclass
class HostResult:
    host: str
    port: int
    state: str = "unknown"
    detail: str = ""
    supported_versions: list = field(default_factory=list)
    preferred: str = ""
    encryption: list = field(default_factory=list)
    compression: list = field(default_factory=list)
    signing: str = "unknown"
    uptime: str = ""
    guid: str = ""
    domain: str = ""
    os: str = ""
    lanmanager: str = ""
    error: str = ""


class SMBVersionScanner(Auxiliary):
    NAME = "SMB Version Scanner"
    DESCRIPTION = (
        "Deep SMB fingerprinting: probes hosts for supported SMB versions "
        "(1/2/3), negotiated dialect, encryption and compression capabilities "
        "(requires SMB 3.1.1), signing requirements, server uptime, GUID, and "
        "authentication domain. Uses impacket's SMBConnection without "
        "authenticating."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True
    REFERENCES = [
        "https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview",
        "https://github.com/fortra/impacket",
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/smb/smb_version.rb",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=445, type=int, description="SMB port (445 or 139)"),
        Option("TIMEOUT", default=5.0, type=float, description="per-host timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first responding host"),
        Option("DEEP", default=True, type=bool,
               description="enable deep fingerprinting (3 connections per host)"),
    ]

    def __init__(self):
        super().__init__()
        try:
            from impacket.smbconnection import SMBConnection  # noqa: F401
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

    def _dialect_name(self, dialect):
        if dialect is None:
            return ""
        if isinstance(dialect, str):
            d = dialect.strip()
            if d.lower().startswith("nt lm"):
                return "SMB 1.0 (NT LM 0.12)"
            return d
        if isinstance(dialect, int):
            return DIALECT_MAP.get(dialect, "SMB 0x{:04x}".format(dialect))
        try:
            code = int(str(dialect), 0)
            return DIALECT_MAP.get(code, "SMB 0x{:04x}".format(code))
        except (ValueError, TypeError):
            return str(dialect)

    def _version_family(self, dialect):
        if isinstance(dialect, str) and dialect.lower().startswith("nt lm"):
            return "1"
        if isinstance(dialect, int):
            if dialect in (SMB2_DIALECT_002, SMB2_DIALECT_21):
                return "2"
            if dialect in (SMB2_DIALECT_30, SMB2_DIALECT_302, SMB2_DIALECT_311):
                return "3"
        return ""

    def _probe_version(self, host, dialect):
        try:
            conn = SMBConnection(
                remoteName=host,
                remoteHost=host,
                sess_port=self.options["RPORT"],
                timeout=self.options["TIMEOUT"],
                preferredDialect=dialect,
            )
            raw = None
            try:
                raw = conn.getDialect()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
            return raw
        except Exception:
            return None

    def _probe_all_versions(self, host):
        versions = []
        raw_dialects = {}

        raw1 = self._probe_version(host, SMB_DIALECT)
        if raw1 is not None:
            versions.append("1")
            raw_dialects["1"] = raw1

        raw2 = self._probe_version(host, SMB2_DIALECT_21)
        if raw2 is not None:
            versions.append("2")
            raw_dialects["2"] = raw2

        raw3 = self._probe_version(host, SMB2_DIALECT_311)
        if raw3 is not None:
            versions.append("3")
            raw_dialects["3"] = raw3

        return versions, raw_dialects

    def _parse_negotiate_contexts(self, conn):
        encryption = []
        compression = []

        try:
            smb3 = conn._SMBConnection
            if not hasattr(smb3, "_NegotiateResponse"):
                return encryption, compression

            resp = smb3._NegotiateResponse
            if not hasattr(resp, "NegotiateContextList"):
                return encryption, compression

            for ctx in resp.NegotiateContextList:
                ctx_type = ctx["ContextType"]

                if ctx_type == SMB2_ENCRYPTION_CAPABILITIES:
                    data = ctx["Data"]
                    if len(data) < 2:
                        continue
                    count = struct.unpack_from("<H", data, 0)[0]
                    for i in range(count):
                        offset = 2 + i * 2
                        if offset + 2 > len(data):
                            break
                        algo_id = struct.unpack_from("<H", data, offset)[0]
                        name = ENCRYPTION_ALGO_MAP.get(
                            algo_id, "Unknown-0x{:04x}".format(algo_id)
                        )
                        encryption.append(name)

                elif ctx_type == SMB2_COMPRESSION_CAPABILITIES:
                    data = ctx["Data"]
                    if len(data) < 8:
                        continue
                    count = struct.unpack_from("<H", data, 0)[0]
                    for i in range(count):
                        offset = 8 + i * 2
                        if offset + 2 > len(data):
                            break
                        algo_id = struct.unpack_from("<H", data, offset)[0]
                        name = COMPRESSION_ALGO_MAP.get(
                            algo_id, "Unknown-0x{:04x}".format(algo_id)
                        )
                        compression.append(name)

        except Exception:
            pass

        return encryption, compression

    def _compute_uptime(self, conn):
        try:
            smb3 = conn._SMBConnection
            if not hasattr(smb3, "_Connection"):
                return ""
            c = smb3._Connection

            system_time = c.get("SystemTime", 0)
            start_time = c.get("ServerStartTime", 0)

            if not system_time or not start_time:
                return ""

            system_sec = system_time / 10_000_000
            start_sec = start_time / 10_000_000
            diff = system_sec - start_sec

            if diff <= 0:
                return ""

            days = int(diff // 86400)
            hours = int((diff % 86400) // 3600)
            minutes = int((diff % 3600) // 60)
            seconds = int(diff % 60)

            parts = []
            if days:
                parts.append("{}d".format(days))
            if hours:
                parts.append("{}h".format(hours))
            if minutes:
                parts.append("{}m".format(minutes))
            if seconds or not parts:
                parts.append("{}s".format(seconds))

            return " ".join(parts)

        except Exception:
            return ""

    def _format_guid(self, guid):
        if not guid:
            return ""
        try:
            if isinstance(guid, bytes):
                if len(guid) == 16:
                    d1 = struct.unpack_from("<I", guid, 0)[0]
                    d2 = struct.unpack_from("<H", guid, 4)[0]
                    d3 = struct.unpack_from("<H", guid, 6)[0]
                    d4 = guid[8:10].hex()
                    d5 = guid[10:16].hex()
                    return "{{{:08x}-{:04x}-{:04x}-{}-{}}}".format(
                        d1, d2, d3, d4, d5
                    )
                return guid.hex()
            s = str(guid).strip()
            if s.startswith("{") and s.endswith("}"):
                return s
            if len(s) == 32 and all(c in "0123456789abcdefABCDEF" for c in s):
                return "{{{}-{}-{}-{}-{}}}".format(
                    s[0:8], s[8:12], s[12:16], s[16:20], s[20:32]
                )
            return s
        except Exception:
            return str(guid)

    def _probe(self, host):
        result = HostResult(host=host, port=self.options["RPORT"])
        timeout = self.options["TIMEOUT"]
        deep = self.options["DEEP"]

        if deep:
            versions, raw_dialects = self._probe_all_versions(host)
            result.supported_versions = versions
        else:
            versions, raw_dialects = [], {}

        conn = None
        try:
            conn = SMBConnection(
                remoteName=host,
                remoteHost=host,
                sess_port=self.options["RPORT"],
                timeout=timeout,
            )
        except socket.timeout:
            result.error = "timeout"
            return result
        except ConnectionRefusedError:
            result.error = "connection refused"
            return result
        except (socket.error, OSError) as e:
            result.error = type(e).__name__
            return result
        except Exception as e:
            result.error = type(e).__name__
            return result

        try:
            try:
                raw_dialect = conn.getDialect()
                result.preferred = self._dialect_name(raw_dialect)
            except Exception:
                pass

            if not deep and result.preferred:
                fam = self._version_family(
                    raw_dialect if "raw_dialect" in dir() else None
                )
                if fam:
                    result.supported_versions = [fam]

            try:
                os_str = conn.getServerOS() or ""
                result.os = str(os_str).strip()
            except Exception:
                pass

            try:
                lm_str = conn.getServerLANManager() or ""
                result.lanmanager = str(lm_str).strip()
            except Exception:
                pass

            try:
                dom_str = conn.getServerDomain() or ""
                result.domain = str(dom_str).strip()
            except Exception:
                pass

            try:
                signing = conn.isSigningRequired()
                result.signing = "required" if signing else "optional"
            except Exception:
                result.signing = "unknown"

            try:
                guid = conn.getServerGUID()
                result.guid = self._format_guid(guid)
            except Exception:
                pass

            result.uptime = self._compute_uptime(conn)

            if deep and "3" in result.supported_versions:
                conn311 = None
                try:
                    conn311 = SMBConnection(
                        remoteName=host,
                        remoteHost=host,
                        sess_port=self.options["RPORT"],
                        timeout=timeout,
                        preferredDialect=SMB2_DIALECT_311,
                    )
                    enc, comp = self._parse_negotiate_contexts(conn311)
                    result.encryption = enc
                    result.compression = comp
                except Exception:
                    pass
                finally:
                    if conn311:
                        try:
                            conn311.close()
                        except Exception:
                            pass

        finally:
            try:
                conn.close()
            except Exception:
                pass

        if result.preferred or result.os or result.lanmanager or result.supported_versions:
            result.state = "up"
        else:
            result.state = "up"

        return result

    def _format_deep_line(self, r):
        parts = []

        if r.supported_versions:
            parts.append("versions: " + ", ".join(r.supported_versions))
        if r.preferred:
            parts.append("preferred dialect: " + r.preferred)
        if r.compression:
            parts.append("compression capabilities: " + ", ".join(r.compression))
        if r.encryption:
            parts.append("encryption capabilities: " + ", ".join(r.encryption))
        if r.signing != "unknown":
            parts.append("signatures: " + r.signing)
        if r.uptime:
            parts.append("uptime: " + r.uptime)
        if r.guid:
            parts.append("guid: " + r.guid)
        if r.domain:
            parts.append("authentication domain: " + r.domain)
        if r.os:
            parts.append("os: " + r.os)

        if not parts:
            return ""

        return "SMB Detected (" + ") (".join(parts) + ")"

    def _print_result(self, r):
        if r.state != "up":
            if r.error:
                print(colors.dimmed("  " + r.host + ": " + r.error))
            return

        line = colors.info(r.host + ":" + str(r.port))
        deep_line = self._format_deep_line(r)
        if deep_line:
            line += " - " + colors.good(deep_line)
        else:
            line += " - " + colors.dimmed("SMB reachable (no banner)")

        print(line)

    def check(self):
        if not self._have_impacket:
            print(colors.bad("impacket is required: pip install impacket"))
            return CheckResult.UNKNOWN

        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + host + ":" + str(self.options["RPORT"])))

        r = self._probe(host)
        self._print_result(r)

        if r.state == "up":
            print(colors.good("check: " + host + " speaks SMB (informational)"))
        elif r.error:
            print(colors.safe("check: " + host + " not reachable (" + r.error + ")"))
        return CheckResult.UNKNOWN

    def action(self):
        if not self._have_impacket:
            print(colors.bad("impacket is required: pip install impacket"))
            return []

        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]
        deep = self.options["DEEP"]

        mode = "deep" if deep else "quick"
        print(colors.info(
            "scanning " + str(len(targets)) + " host(s) with "
            + str(threads) + " threads (" + mode + " mode)"
        ))

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

                    if r.state == "up":
                        hits.append(r)
                        line = r.host
                        if r.supported_versions:
                            line += "  SMB " + ",".join(r.supported_versions)
                        if r.preferred:
                            line += "  " + r.preferred
                        if r.os:
                            line += "  " + r.os
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
        print("  smb up:       " + colors.green(str(len(hits))))
        print("  no response:  " + colors.dimmed(str(clean)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))

        if hits:
            print(colors.heading("  smb hosts:"))
            for h in hits:
                line = "    " + colors.info(h.host + ":" + str(h.port))
                deep_line = self._format_deep_line(h)
                if deep_line:
                    line += " - " + colors.good(deep_line)
                print(line)

        return hits
