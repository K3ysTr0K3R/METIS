import socket
import threading
import time
import uuid


class Session:
    def __init__(self, sock, addr):
        self.id = uuid.uuid4().hex[:8]
        self.sock = sock
        self.addr = addr
        self.created_at = time.time()
        self.alive = True
        self.lock = threading.Lock()
        self.line_terminator = "\n"

    def send(self, data: bytes) -> bool:
        if not self.alive:
            return False
        try:
            with self.lock:
                if hasattr(self.sock, "sendall"):
                    self.sock.sendall(data)
                elif hasattr(self.sock, "send"):
                    self.sock.send(data)
                else:
                    raise OSError("socket has no send/sendall")
            return True
        except (BrokenPipeError, ConnectionResetError,
                ConnectionAbortedError, OSError):
            self.alive = False
            return False

    def recv(self, timeout: float = 2.0) -> bytes:
        if not self.alive:
            return b""
        try:
            self.sock.settimeout(timeout)
            data = self.sock.recv(4096)
            if not data:
                if isinstance(self.sock, socket.socket):
                    self.alive = False
                return b""
            return data
        except socket.timeout:
            return b""
        except (BrokenPipeError, ConnectionResetError,
                ConnectionAbortedError, OSError):
            self.alive = False
            return b""

    def shell(self, command: str, timeout: float = 8.0,
              idle_break: float = 1.0, first_byte_wait: float = 2.0) -> str:
        if not self.alive:
            return ""
        payload = (command + self.line_terminator).encode()
        if not self.send(payload):
            return ""

        chunks = []
        start = time.time()
        got_first = False
        last_data_at = time.time()

        while True:
            if (time.time() - start) > timeout:
                break
            data = self.recv(timeout=0.3)
            if not self.alive:
                break
            if data:
                chunks.append(data)
                got_first = True
                last_data_at = time.time()
                continue
            if not got_first:
                if (time.time() - start) > first_byte_wait:
                    break
            else:
                if (time.time() - last_data_at) > idle_break:
                    break

        return b"".join(chunks).decode(errors="replace")

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass

    def __repr__(self):
        return f"<Session {self.id} {self.addr[0]}:{self.addr[1]}>"
