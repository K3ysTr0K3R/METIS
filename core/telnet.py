import select
import time

class T:
    IAC = 255
    SE = 240
    NOP = 241
    SB = 250
    WILL = 251
    WONT = 252
    DO = 253
    DONT = 254

class O:
    ENVIRON = 39
    TERMINAL_TYPE = 24
    NAWS = 31
    BINARY = 0
    SGA = 3
    ECHO = 1

def build_environ_var(name: str, value: str) -> bytes:
    """Build IAC SB ENVIRON IS VAR <name> VALUE <value> IAC SE."""
    p = bytearray([T.IAC, T.SB, O.ENVIRON, 0])
    p.append(0)
    p.extend(name.encode("ascii"))
    p.append(1)
    p.extend(value.encode("ascii"))
    p.extend([T.IAC, T.SE])
    return bytes(p)

class TelnetHandler:
    def __init__(self, sock):
        self.sock = sock

    def feed(self, data: bytes) -> bytes:
        """Consume raw bytes, return clean application data."""
        clean = bytearray()
        i = 0
        n = len(data)
        while i < n:
            if data[i] != T.IAC:
                clean.append(data[i])
                i += 1
                continue
            if i + 1 >= n:
                break
            cmd = data[i + 1]
            if cmd in (T.DO, T.DONT, T.WILL, T.WONT):
                if i + 2 >= n:
                    break
                opt = data[i + 2]
                self._respond(cmd, opt)
                i += 3
            elif cmd == T.SB:
                i = self._skip_sb(data, i + 2)
            elif cmd == T.NOP:
                self._send_nop()
                i += 2
            else:
                i += 2
        return bytes(clean)

    def _respond(self, cmd, opt):
        resp = None
        if cmd == T.DO:
            if opt in (O.SGA, O.ECHO, O.ENVIRON):
                resp = bytes([T.IAC, T.WILL, opt])
            else:
                resp = bytes([T.IAC, T.WONT, opt])
        elif cmd == T.WILL:
            if opt in (O.SGA, O.ECHO, O.ENVIRON):
                resp = bytes([T.IAC, T.DO, opt])
            else:
                resp = bytes([T.IAC, T.DONT, opt])
        if resp:
            try:
                self.sock.sendall(resp)
            except OSError:
                pass

    def _send_nop(self):
        try:
            self.sock.sendall(bytes([T.IAC, T.NOP]))
        except OSError:
            pass

    def _skip_sb(self, data, start):
        i = start
        n = len(data)
        while i < n:
            if data[i] == T.IAC and i + 1 < n and data[i + 1] == T.SE:
                return i + 2
            i += 1
        return n

    def read_clean(self, timeout: float = 2.0) -> bytes:
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            return b""
        try:
            data = self.sock.recv(4096)
        except OSError:
            return b""
        if not data:
            return b""
        return self.feed(data)
