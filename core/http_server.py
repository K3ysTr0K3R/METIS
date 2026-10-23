import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from core import colors

class _PayloadServer(HTTPServer):
    def __init__(self, addr, handler, payload_map):
        super().__init__(addr, handler)
        self.payload_map = payload_map


class _PayloadHandler(BaseHTTPRequestHandler):
    server_version = "demo/0.4"

    def do_GET(self):
        entry = self.server.payload_map.get(self.path)
        if not entry:
            self.send_response(404)
            self.end_headers()
            return
        body, content_type = entry
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(colors.good(f"served {self.path} to {self.client_address[0]}"))

    def log_message(self, *args, **kwargs):
        pass


class ThreadedHTTPPayloadServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.httpd: HTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.payload_map: dict[str, tuple[bytes, str]] = {}

    def register(self, path: str, content: bytes | str,
                 content_type: str = "application/xml"):
        if isinstance(content, str):
            content = content.encode()
        self.payload_map[path] = (content, content_type)

    def start(self):
        if self.httpd:
            return self
        self.httpd = _PayloadServer(
            (self.host, self.port), _PayloadHandler, self.payload_map
        )
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        print(colors.info(f"payload server up on {self.host}:{self.port}"))
        return self

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        print(colors.info("payload server stopped"))

    def url_for(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"http://{self.host}:{self.port}{path}"
