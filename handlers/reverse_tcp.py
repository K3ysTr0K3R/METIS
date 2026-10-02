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

    def run(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.lhost, self.lport))
        srv.listen(5)
        srv.settimeout(1.0)
        print(colors.info(f"handler listening on {self.lhost}:{self.lport}"))
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            session = Session(conn, addr)
            self.sessions.add(session)
        srv.close()
        print(colors.info("handler stopped"))

    def stop(self):
        self._stop.set()
