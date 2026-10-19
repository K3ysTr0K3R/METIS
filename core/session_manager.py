import threading
from core import colors
from core.session import Session


def _session_address(session):
    if isinstance(getattr(session, "addr", None), tuple) and session.addr:
        return session.addr[0]
    return None


def _session_kind(session):
    name = type(session).__name__
    kind = name.replace("Session", "").lower()
    return kind or "shell"


class SessionManager:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self.db = None

    def add(self, session: Session) -> Session:
        with self._lock:
            self._sessions[session.id] = session
        print(colors.good(f"new session: {session}"))
        if self.db:
            try:
                self.db.add_session_record(
                    session.id,
                    address=_session_address(session),
                    kind=_session_kind(session),
                )
            except Exception:
                pass
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
        from core.webshell import WebShellSession
        ws = WebShellSession(url, method=method,
                             cmd_param=cmd_param, session=session)
        return self.add(ws)

    def add_channel(self, channel, addr) -> "Session":
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
            if self.db:
                try:
                    self.db.close_session_record(sid)
                except Exception:
                    pass
            print(colors.warn(f"session {sid} closed"))

    def reap(self):
        with self._lock:
            dead = [sid for sid, s in self._sessions.items() if not s.alive]
            for sid in dead:
                del self._sessions[sid]
        for sid in dead:
            if self.db:
                try:
                    self.db.close_session_record(sid)
                except Exception:
                    pass
            print(colors.warn(f"reaped dead session {sid}"))

    def close_all(self):
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for s in sessions:
            s.close()
            if self.db:
                try:
                    self.db.close_session_record(s.id)
                except Exception:
                    pass
