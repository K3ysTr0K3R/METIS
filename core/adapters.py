class ChannelAdapter:
    def __init__(self, channel, timeout: float = 5.0):
        self.ch = channel
        self._timeout = timeout
        self._closed = False

    def sendall(self, data: bytes) -> None:
        if self._closed:
            raise OSError("channel closed")
        self.ch.sendall(data)

    def recv(self, n: int) -> bytes:
        if self._closed:
            return b""
        try:
            if self.ch.recv_ready():
                return self.ch.recv(n)
            if self.ch.exit_status_ready() and not self.ch.recv_ready():
                return b""
        except Exception:
            pass
        return self.ch.recv(n)

    def settimeout(self, t) -> None:
        self._timeout = t
        try:
            self.ch.settimeout(t)
        except Exception:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.ch.close()
        except Exception:
            pass

    def fileno(self) -> int:
        try:
            return self.ch.fileno()
        except Exception:
            return -1


class StreamAdapter:
    def __init__(self, stream):
        self.stream = stream
        self._timeout = None

    def sendall(self, data: bytes) -> None:
        if hasattr(self.stream, "write"):
            self.stream.write(data)
            if hasattr(self.stream, "flush"):
                self.stream.flush()
        elif hasattr(self.stream, "sendall"):
            self.stream.sendall(data)

    def recv(self, n: int) -> bytes:
        if hasattr(self.stream, "read"):
            return self.stream.read(n)
        if hasattr(self.stream, "recv"):
            return self.stream.recv(n)
        return b""

    def settimeout(self, t) -> None:
        self._timeout = t
        if hasattr(self.stream, "settimeout"):
            self.stream.settimeout(t)

    def close(self) -> None:
        try:
            self.stream.close()
        except Exception:
            pass

    def fileno(self) -> int:
        try:
            return self.stream.fileno()
        except Exception:
            return -1
