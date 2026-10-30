import socket
import threading
from core import colors
from core.session import Session
from core.session_manager import SessionManager

class ReverseTCPHandler(threading.Thread):
    def __init__(self, lhost: str, lport: int, session_manager: SessionManager):
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
                f"handler bind {self.lhost}:{self.lport} failed: {e}"
            ))
            srv.close()
            return

        try:
            srv.listen(5)
        except OSError as e:
            print(colors.bad(f"handler listen failed: {e}"))
            srv.close()
            return

        srv.settimeout(1.0)
        self._srv = srv
        print(colors.info(f"handler listening on {self.lhost}:{self.lport}"))

        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                session = Session(conn, addr)
                self.sessions.add(session)
            except Exception as e:
                print(colors.bad(f"handler: session setup failed: {e}"))
                try:
                    conn.close()
                except OSError:
                    pass

        try:
            srv.close()
        except OSError:
            pass
        self._srv = None

    def stop(self, quiet: bool = False):
        self._stop.set()
        srv = self._srv
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
