import socket
from concurrent.futures import ThreadPoolExecutor

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
            return host, port, True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return host, port, False
        finally:
            s.close()

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
            for fut in futures:
                host, port, is_open = fut.result()
                if is_open:
                    open_ports.append((host, port))
                    print(colors.good(f"{host}:{port} open"))

        print(colors.info(f"done. {len(open_ports)} open port(s)."))
        return open_ports
