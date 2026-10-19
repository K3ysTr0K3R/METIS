import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core import colors
from core.auxiliary import Auxiliary
from core.module import Option

class TCPConnectScanner(Auxiliary):
    NAME = "TCP Connect Port Scanner"
    DESCRIPTION = (
        "Scan a host or subnet for open TCP ports using connect(). "
        "Supports single hosts, comma lists, CIDR, ranges, and file: specs."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = False

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("PORTS", default="22,80,443",
               description="comma list or range (e.g. 22,80,1000-2000)"),
        Option("TIMEOUT", default=1.0, type=float, description="per-port timeout"),
        Option("THREADS", default=50, type=int, description="concurrency"),
    ]

    def _expand_targets(self) -> list[str]:
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info(f"target list -> {len(hosts)} hosts"))
        return hosts

    def _parse_ports(self):
        spec = self.options["PORTS"]
        ports = set()
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.update(range(int(lo), int(hi) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def _scan_one(self, host, port, timeout):
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            banner = ""
            try:
                s.settimeout(max(timeout, 0.5))
                raw = s.recv(256)
                if raw and all(0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d) for b in raw):
                    banner = raw.decode("ascii", errors="ignore").strip()
            except (socket.timeout, OSError):
                banner = ""
            return host, port, True, banner
        except (socket.timeout, ConnectionRefusedError, OSError):
            return host, port, False, ""
        finally:
            s.close()

    def _record_open_port(self, host, port, banner):
        db = self._db()
        if not db:
            return
        try:
            db.ensure_host(host, state="up")
            db.add_service(
                host, port,
                proto="tcp",
                state="open",
                banner=banner[:200] if banner else "",
            )
        except Exception:
            pass

    def action(self):
        targets = self._expand_targets()
        ports = self._parse_ports()
        timeout = self.options["TIMEOUT"]
        workers = self.options["THREADS"]

        total = len(targets) * len(ports)
        print(colors.info(
            f"scanning {len(targets)} host(s) x {len(ports)} port(s) "
            f"= {total} probes, {workers} workers"
        ))

        open_ports = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [
                ex.submit(self._scan_one, h, p, timeout)
                for h in targets for p in ports
            ]
            for fut in as_completed(futures):
                host, port, is_open, banner = fut.result()
                if not is_open:
                    continue
                open_ports.append((host, port))
                display = f"{host}:{port} open"
                if banner:
                    display += f"  [{banner.splitlines()[0][:60]}]"
                print(colors.good(display))
                self._record_open_port(host, port, banner)

        db = self._db()
        if db and db.current_workspace_id():
            try:
                db.log_event(
                    f"tcp_connect scan: {len(targets)} host(s), "
                    f"{len(ports)} port(s), {len(open_ports)} open",
                    kind="scan",
                )
            except Exception:
                pass

        print(colors.info(f"done. {len(open_ports)} open port(s)."))
        return open_ports
