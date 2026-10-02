import threading
from core import colors
from core.session import Session

class SessionManager:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def add(self, session: Session) -> Session:
        with self._lock:
            self._sessions[session.id] = session
        print(colors.good(f"new session: {session}"))
        return session

    def add_socket(self, sock, addr) -> Session:
        session = Session(sock, addr)
        return self.add(session)

    def get(self, sid: str) -> Session | None:
        return self._sessions.get(sid)

    def list(self) -> list[Session]:
        return list(self._sessions.values())

    def __len__(self) -> int:
        return len(self._sessions)

    def add_webshell(self, url: str, method: str = "get",
                     cmd_param: str = "cmd", session=None) -> "Session":
        """Register an HTTP-based webshell as a Session."""
        from core.webshell import WebShellSession
        ws = WebShellSession(url, method=method,
                             cmd_param=cmd_param, session=session)
        return self.add(ws)

    def add_channel(self, channel, addr) -> "Session":
        """Register a paramiko Channel as a Session via ChannelAdapter."""
        from core.adapters import ChannelAdapter
        adapter = ChannelAdapter(channel)
        return self.add_socket(adapter, addr)

    def __contains__(self, sid: str) -> bool:
        return sid in self._sessions

    def remove(self, sid: str):
        with self._lock:
            s = self._sessions.pop(sid, None)
        if s:
            s.close()
            print(colors.warn(f"session {sid} closed"))

    def reap(self):
        with self._lock:
            dead = [sid for sid, s in self._sessions.items() if not s.alive]
            for sid in dead:
                del self._sessions[sid]
        for sid in dead:
            print(colors.warn(f"reaped dead session {sid}"))

    def close_all(self):
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for s in sessions:
            s.close()
