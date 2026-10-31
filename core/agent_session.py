import json
import socket
import struct
import time
from core.session import Session

class MetisAgentSession(Session):
    agent = True

    def __init__(self, sock, addr, sysinfo=None):
        super().__init__(sock, addr)
        self.sysinfo = sysinfo or {}
        self._rbuf = b""

    def __repr__(self):
        return f"<MetisAgentSession {self.id} {self.addr[0]}:{self.addr[1]}>"

    def _recv_exact(self, n, timeout=2.0, max_wait=40.0):
        start = time.time()
        while len(self._rbuf) < n and self.alive:
            if time.time() - start > max_wait:
                self.alive = False
                return b""
            chunk = self.recv(timeout=timeout)
            if chunk:
                self._rbuf += chunk
        if len(self._rbuf) < n:
            return b""
        result = self._rbuf[:n]
        self._rbuf = self._rbuf[n:]
        return result

    def _recv_msg(self, timeout=2.0, max_wait=40.0):
        header = self._recv_exact(4, timeout=timeout, max_wait=max_wait)
        if len(header) < 4:
            return None
        n = struct.unpack("!I", header)[0]
        if n > 1048576:
            self.alive = False
            return None
        payload = self._recv_exact(n, timeout=timeout, max_wait=max_wait)
        if len(payload) < n:
            return None
        try:
            return json.loads(payload.decode())
        except ValueError:
            return None

    def _send_msg(self, obj):
        data = json.dumps(obj).encode()
        framed = struct.pack("!I", len(data)) + data
        return self.send(framed)

    def _rpc(self, cmd, args=None, data=None, timeout=30.0):
        msg = {"cmd": cmd, "args": args or []}
        if data is not None:
            msg["data"] = data
        if not self._send_msg(msg):
            return {"ok": False, "error": "send failed"}
        resp = self._recv_msg(timeout=2.0, max_wait=timeout)
        if resp is None:
            return {"ok": False, "error": "no response"}
        return resp

    def shell(self, command, timeout=30.0, **kwargs):
        if not self.alive:
            return ""
        parts = command.strip().split(None, 1)
        head = parts[0] if parts else ""
        args = parts[1] if len(parts) > 1 else ""

        if head == "agent_help":
            return (
                "  agent_help                 this message\n"
                "  agent_sysinfo              full sysinfo\n"
                "  agent_getuid               uid/gid\n"
                "  agent_pwd                  current directory\n"
                "  agent_cd <path>            change directory (persists)\n"
                "  agent_ls [path]            list directory\n"
                "  agent_ps                   process list\n"
                "  agent_mkdir <path>         create directory\n"
                "  agent_rm <path>            remove file or dir\n"
                "  agent_download <path>      download remote file\n"
                "  agent_upload <local> [remote]  upload local file\n"
                "  agent_exit                 close session\n"
            )

        if head == "agent_sysinfo":
            r = self._rpc("sysinfo")
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            s = r.get("sysinfo") or {}
            return (
                "hostname: " + str(s.get("hostname", "?")) + "\n"
                "os:       " + str(s.get("os", "?")) + " " + str(s.get("release", "")) + "\n"
                "machine:  " + str(s.get("machine", "?")) + "\n"
                "python:   " + str(s.get("python", "?")) + "\n"
                "user:     " + str(s.get("user", "?")) + "\n"
                "cwd:      " + str(s.get("cwd", "?")) + "\n"
                "uid/gid:  " + str(s.get("uid", "?")) + "/" + str(s.get("gid", "?")) + "\n"
            )

        if head == "agent_getuid":
            r = self._rpc("getuid")
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            return "uid=" + str(r.get("uid", "?")) + " gid=" + str(r.get("gid", "?")) + "\n"

        if head == "agent_pwd":
            r = self._rpc("pwd")
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            return r.get("cwd", "") + "\n"

        if head == "agent_cd":
            r = self._rpc("cd", [args.strip() or "."])
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            return r.get("cwd", "") + "\n"

        if head == "agent_ls":
            r = self._rpc("ls", [args.strip() or "."])
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            lines = []
            for e in r.get("entries", []):
                suffix = "/" if e.get("type") == "dir" else ""
                lines.append(e.get("name", "?") + suffix)
            return "\n".join(lines) + "\n"

        if head == "agent_ps":
            r = self._rpc("ps", timeout=15)
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            return r.get("stdout", "") + r.get("stderr", "")

        if head == "agent_mkdir":
            r = self._rpc("mkdir", [args.strip()])
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            return "created " + r.get("path", "?") + "\n"

        if head == "agent_rm":
            r = self._rpc("rm", [args.strip()])
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            return "removed " + r.get("path", "?") + "\n"

        if head == "agent_download":
            rp = args.strip()
            if not rp:
                return "usage: agent_download <remote_path>\n"
            r = self._rpc("download", [rp])
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            import base64 as _b64
            data = _b64.b64decode(r.get("data", ""))
            local = "/tmp/" + rp.replace("/", "_")
            try:
                with open(local, "wb") as f:
                    f.write(data)
                return "saved " + str(len(data)) + " bytes to " + local + "\n"
            except Exception as e:
                return "save failed: " + str(e) + "\n"

        if head == "agent_upload":
            raw = args.strip()
            if not raw:
                return "usage: agent_upload <local_path> [remote_path]\n"
            parts2 = raw.split(None, 1)
            lp = parts2[0]
            rp = parts2[1] if len(parts2) > 1 else "/tmp/" + lp.rsplit("/", 1)[-1]
            try:
                with open(lp, "rb") as f:
                    data = f.read()
            except Exception as e:
                return "read failed: " + str(e) + "\n"
            r = self.upload(rp, data)
            if not r.get("ok"):
                return (r.get("error", "?") + "\n")
            return "uploaded " + str(r.get("size", len(data))) + " bytes to " + rp + "\n"

        if head == "agent_exit":
            self.close()
            return "bye\n"

        resp = self._rpc("exec", [command], timeout=timeout)
        if not resp.get("ok"):
            err = resp.get("error", "unknown error")
            if resp.get("stderr"):
                return resp.get("stdout", "") + resp.get("stderr", "")
            return "error: " + str(err) + "\n"
        out = resp.get("stdout", "")
        err = resp.get("stderr", "")
        return out + err

    def getuid(self):
        return self._rpc("getuid")

    def sysinfo_full(self):
        return self._rpc("sysinfo")

    def cd(self, path):
        return self._rpc("cd", [path])

    def pwd(self):
        return self._rpc("pwd")

    def ls(self, path="."):
        return self._rpc("ls", [path])

    def ps(self):
        return self._rpc("ps", timeout=15)

    def mkdir(self, path):
        return self._rpc("mkdir", [path])

    def rm(self, path):
        return self._rpc("rm", [path])

    def download(self, remote_path):
        return self._rpc("download", [remote_path])

    def upload(self, remote_path, data_bytes):
        import base64 as _b64
        return self._rpc(
            "upload", [remote_path], data=_b64.b64encode(data_bytes).decode()
        )

    def close(self):
        try:
            self._send_msg({"cmd": "exit"})
        except Exception:
            pass
        super().close()
