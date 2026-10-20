import os
import shlex
import subprocess
import sys
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from core import colors
from core.module_manager import ModuleManager
from core.session_manager import SessionManager
from core.database import Database
from handlers.reverse_tcp import ReverseTCPHandler


GRADIENT_PRESETS = {
    "synthwave": [51, 45, 39, 135, 171, 201],
    "fire":      [226, 220, 214, 208, 202, 196],
    "ice":       [153, 117, 111, 105, 99, 63],
    "toxic":     [118, 154, 190, 226, 220, 214],
    "matrix":    [22, 28, 34, 40, 46, 82, 118, 154, 190],
    "sunset":    [213, 207, 201, 197, 203, 209],
    "mono":      [240, 245, 250, 255],
    "rainbow":   [196, 208, 220, 46, 51, 21, 93, 201],
    "ocean":     [17, 18, 19, 20, 33, 39, 45, 51],
    "ember":     [88, 124, 160, 196, 202, 208],
}


class MetisCompleter(Completer):
    def __init__(self, console):
        self.console = console

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        parts = text.split()

        if not parts:
            for name in self._command_names():
                yield Completion(name, start_position=0)
            return

        if text.endswith(" ") and len(parts) == 1:
            cmd = parts[0]
            for item in self._args_for(cmd, ""):
                yield Completion(item, start_position=0)
            return

        if len(parts) == 1 and not text.endswith(" "):
            word = parts[0]
            for name in self._command_names():
                if name.startswith(word):
                    yield Completion(name, start_position=-len(word))
            return

        cmd = parts[0]
        word = parts[-1] if not text.endswith(" ") else ""
        prefix_start = -len(word) if word else 0
        for item in self._args_for(cmd, word):
            yield Completion(item, start_position=prefix_start)

    def _command_names(self):
        names = []
        for n in dir(self.console):
            if n.startswith("do_"):
                names.append(n[3:])
        return sorted(names)

    def _args_for(self, cmd, partial):
        c = self.console
        if cmd in ("use", "info"):
            for p in c.modules.list():
                if p.startswith(partial):
                    yield p
            return
        if cmd == "theme":
            for t in colors.list_themes():
                if t.startswith(partial):
                    yield t
            return
        if cmd in ("interact", "kill"):
            for s in c.sessions.list():
                if s.id.startswith(partial):
                    yield s.id
            return
        if cmd == "show":
            for o in ("modules", "options", "info", "globals", "themes",
                      "payloads", "spool", "workspaces", "hosts", "services",
                      "vulns", "creds", "notes", "loot", "events"):
                if o.startswith(partial):
                    yield o
            return
        if cmd in ("set", "unset"):
            if c.active_module:
                for name in c.active_module.options:
                    if name.startswith(partial.upper()):
                        yield name
            return
        if cmd in ("setg", "unsetg"):
            for name in c.global_options:
                if name.startswith(partial.upper()):
                    yield name
            return
        if cmd == "workspace":
            if c.db:
                for w in c.db.list_workspaces():
                    if w["name"].startswith(partial):
                        yield w["name"]
            return
        if cmd in ("hosts", "vulns", "creds", "notes", "loot"):
            if c.db:
                for h in c.db.list_hosts():
                    if h["address"].startswith(partial):
                        yield h["address"]
            return
        if cmd == "services":
            if c.db:
                for h in c.db.list_hosts():
                    if h["address"].startswith(partial):
                        yield h["address"]
            return
        if cmd == "db_import":
            try:
                for entry in sorted(os.listdir(c._local_cwd)):
                    if not entry.lower().endswith(".xml"):
                        continue
                    if entry.startswith(partial):
                        yield entry
            except OSError:
                pass
            return


class Console:
    BASE_PROMPT = "metis"
    VERSION = "1.4.0"
    REPO = "K3ysTr0K3R/METIS"
    BANNER = (
        "███╗   ███╗███████╗████████╗██╗███████╗\n"
        "████╗ ████║██╔════╝╚══██╔══╝██║██╔════╝\n"
        "██╔████╔██║█████╗     ██║   ██║███████╗\n"
        "██║╚██╔╝██║██╔══╝     ██║   ██║╚════██║\n"
        "██║ ╚═╝ ██║███████╗   ██║   ██║███████║\n"
        "╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝╚══════╝\n"
        "K3ysTr0K3R                    v1.4.0\n"
        "\n"
        "Modular Exploitation & Threat Intelligence Framework\n"
    )

    def __init__(self):
        self.db = Database()
        self.sessions = SessionManager()
        self.sessions.db = self.db
        self.modules = ModuleManager(root="modules")
        self.handlers = []
        self.active_module = None
        self.active_path = None
        self.global_options = {}
        self.last_search = []
        self.running = True
        self._local_cwd = os.getcwd()
        self._skip_update = "--no-update-check" in sys.argv
        self._spool_file = None

        self._config_path = os.path.expanduser("~/.metis_config")
        self._load_globals()

        history_path = os.path.expanduser("~/.metis_history")
        try:
            os.makedirs(os.path.dirname(history_path), exist_ok=True)
        except Exception:
            pass

        self._session = PromptSession(
            history=FileHistory(history_path),
            auto_suggest=AutoSuggestFromHistory(),
            completer=MetisCompleter(self),
            complete_while_typing=True,
        )

    def _load_globals(self):
        if not os.path.isfile(self._config_path):
            return
        try:
            with open(self._config_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        self.global_options[k.strip().upper()] = v.strip()
        except Exception:
            pass

    def _save_globals(self):
        try:
            with open(self._config_path, "w") as f:
                f.write("# metis global options\n")
                for k, v in sorted(self.global_options.items()):
                    f.write(f"{k}={v}\n")
        except Exception:
            pass

    def _spool(self, text):
        if not self._spool_file:
            return
        try:
            with open(self._spool_file, "a") as f:
                f.write(text + "\n")
        except Exception:
            pass

    def _check_update_silent(self):
        if self._skip_update:
            return
        import urllib.request
        import json
        try:
            req = urllib.request.Request(
                "https://api.github.com/repos/" + self.REPO + "/releases/latest",
                headers={"User-Agent": "metis-updater"},
            )
            with urllib.request.urlopen(req, timeout=3) as r:
                data = json.loads(r.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != self.VERSION:
                print(colors.warn(
                    "update available: v" + self.VERSION + " -> v" + latest
                    + " (run 'update')"
                ))
        except Exception:
            pass

    def do_update(self, args):
        """update  — check GitHub for a newer release and pull if available"""
        import urllib.request
        import json

        api = "https://api.github.com/repos/" + self.REPO + "/releases/latest"
        current = self.VERSION

        print(colors.info("current version: v" + current))
        print(colors.info("checking " + self.REPO + "..."))

        try:
            req = urllib.request.Request(api, headers={"User-Agent": "metis-updater"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
        except Exception as e:
            print(colors.bad("could not reach GitHub: " + str(e)))
            return

        latest = data.get("tag_name", "").lstrip("v")
        if not latest:
            print(colors.bad("no tag_name in release response"))
            return

        print(colors.dimmed("  latest:  v" + latest))

        if latest == current:
            print(colors.good("already up to date"))
            return

        print(colors.warn("update available: v" + current + " -> v" + latest))
        print(colors.dimmed("  release: " + str(data.get("html_url", ""))))

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        try:
            r = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=project_root,
                capture_output=True, text=True, timeout=5,
            )
            if r.stdout.strip() != "true":
                raise RuntimeError("not a git repo")
        except Exception:
            print(colors.bad("not a git clone — download manually:"))
            print(colors.dimmed("  " + str(data.get("html_url", ""))))
            return

        print(colors.info("pulling updates via git..."))
        try:
            r = subprocess.run(
                ["git", "pull", "origin", "main"],
                cwd=project_root,
                capture_output=True, text=True, timeout=60,
            )
            out = (r.stdout or "").strip()
            err = (r.stderr or "").strip()
            if out:
                print(out)
            if err:
                print(colors.dimmed(err))
            if r.returncode == 0:
                print(colors.good("update complete — restart metis to apply"))
            else:
                print(colors.bad("git pull failed"))
        except Exception as e:
            print(colors.bad("git pull error: " + str(e)))

    def prompt(self):
        user_color = colors.wrap_fallback("prompt_user", "prompt")
        cat_color = colors.wrap_fallback("prompt_category", "prompt")
        path_color = colors.wrap("prompt")

        ws = self.db.current_workspace() if self.db else None
        ws_tag = colors.dimmed(f"[{ws}] ") if ws else ""

        base = self.BASE_PROMPT
        if self.active_path:
            category, _, rest = self.active_path.partition("/")
            src = ""
            if self.active_module and self.active_module.options.get("SOURCE"):
                src = colors.good(" [src]")
            user = user_color(base)
            cat = cat_color(category)
            rest_padded = path_color(f"({rest})") if rest else ""
            return f"{user} {ws_tag}{cat}{rest_padded}{src}{user_color(' > ')}"
        if ws:
            return f"{user_color(base)} {ws_tag}{user_color('> ')}"
        return user_color(f"{base} > ")

    def _run_local(self, cmd, echo=False):
        if echo:
            print(colors.dimmed(f"[*] exec: {cmd}"))
        try:
            subprocess.run(cmd, shell=True, cwd=self._local_cwd)
        except KeyboardInterrupt:
            print()
            print(colors.warn("interrupted"))
        except Exception as e:
            print(colors.bad(f"local command failed: {e}"))

    def do_shell(self, args):
        """shell  — drop into an interactive local shell"""
        shell_bin = os.environ.get("SHELL", "/bin/bash")
        print(colors.info(f"dropping to {shell_bin} — type 'exit' to return"))
        try:
            subprocess.run([shell_bin], cwd=self._local_cwd)
        except FileNotFoundError:
            print(colors.bad(f"shell not found: {shell_bin}"))
            return
        except KeyboardInterrupt:
            print()
        print(colors.info("back in metis"))

    def do_exec(self, args):
        """exec <cmd>  — run a local shell command"""
        cmd = args.strip()
        if not cmd:
            print(colors.warn("usage: exec <command>"))
            return
        self._run_local(cmd)

    def do_cd(self, args):
        """cd <dir>  — change the framework's local working directory"""
        target = args.strip()
        if not target:
            target = os.path.expanduser("~")
        if not os.path.isabs(target):
            target = os.path.join(self._local_cwd, target)
        target = os.path.normpath(os.path.expanduser(target))
        if not os.path.isdir(target):
            print(colors.bad(f"not a directory: {target}"))
            return
        self._local_cwd = target
        print(colors.dimmed(f"  cwd: {self._local_cwd}"))

    def do_pwd(self, _):
        """pwd  — print the framework's local working directory"""
        print(self._local_cwd)

    def do_ls(self, args):
        """ls [path]  — list local directory contents"""
        path = args.strip() or "."
        if not os.path.isabs(path):
            path = os.path.join(self._local_cwd, path)
        path = os.path.normpath(os.path.expanduser(path))
        if not os.path.isdir(path):
            print(colors.bad(f"not a directory: {path}"))
            return
        try:
            entries = sorted(os.listdir(path))
        except OSError as e:
            print(colors.bad(str(e)))
            return
        for name in entries:
            full = os.path.join(path, name)
            if os.path.isdir(full):
                print(colors.session(name + "/"))
            elif os.access(full, os.X_OK):
                print(colors.good(name + "*"))
            else:
                print(name)

    def do_cat(self, args):
        """cat <file>  — print a local file"""
        path = args.strip()
        if not path:
            print(colors.warn("usage: cat <file>"))
            return
        if not os.path.isabs(path):
            path = os.path.join(self._local_cwd, path)
        path = os.path.normpath(os.path.expanduser(path))
        try:
            with open(path, "r", errors="replace") as f:
                sys.stdout.write(f.read())
        except OSError as e:
            print(colors.bad(str(e)))

    def do_env(self, _):
        """env  — print local environment variables"""
        for k in sorted(os.environ):
            print(f"  {k}={os.environ[k]}")

    def do_which(self, args):
        """which <cmd>  — locate a binary on the local PATH"""
        name = args.strip()
        if not name:
            print(colors.warn("usage: which <cmd>"))
            return
        import shutil
        path = shutil.which(name)
        if path:
            print(path)
        else:
            print(colors.bad(f"not found: {name}"))

    def do_listen(self, args):
        """listen <lhost> <lport>  — start a reverse TCP handler"""
        parts = shlex.split(args)
        if len(parts) != 2:
            print(colors.warn("usage: listen <lhost> <lport>"))
            return
        try:
            lhost, lport = parts[0], int(parts[1])
        except ValueError:
            print(colors.bad("lport must be an integer"))
            return
        h = ReverseTCPHandler(lhost, lport, self.sessions)
        h.start()
        self.handlers.append(h)

    def do_connect(self, args):
        """connect <host> <port>  — connect to a bind shell"""
        import socket as _socket
        parts = args.strip().split()
        if len(parts) != 2:
            print(colors.warn("usage: connect <host> <port>"))
            return
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            print(colors.bad("port must be an integer"))
            return
        try:
            s = _socket.create_connection((host, port), timeout=5)
        except OSError as e:
            print(colors.bad("connection failed: " + str(e)))
            return
        print(colors.good("connected to " + host + ":" + str(port)))
        self.sessions.add_socket(s, (host, port))

    def do_handlers(self, _):
        """handlers  — list active handlers"""
        if not self.handlers:
            print(colors.info("no active handlers"))
            return
        for i, h in enumerate(self.handlers):
            print(f"  [{i}] {h.lhost}:{h.lport}")

    def do_kill_handler(self, args):
        """kill_handler <index>  — stop a handler by index"""
        try:
            idx = int(args.strip())
            h = self.handlers.pop(idx)
        except (ValueError, IndexError):
            print(colors.warn("usage: kill_handler <index>"))
            return
        h.stop()
        print(colors.info(f"handler {idx} stopped"))

    def do_sessions(self, _):
        """sessions  — list active sessions"""
        self.sessions.reap()
        sess = self.sessions.list()
        if not sess:
            print(colors.info("no active sessions"))
            return
        for s in sess:
            state = colors.green("alive") if s.alive else colors.red("dead")
            print(f"  {colors.session(s.id)}  {s.addr[0]}:{s.addr[1]}  ({state})")

    def _sync_session(self, s, timeout=4.0):
        import time as _t
        start = _t.time()
        got = b""
        while _t.time() - start < timeout:
            data = s.recv(timeout=0.3)
            if data:
                got += data
            elif got:
                break
        if got:
            try:
                text = got.decode(errors="replace")
                print(colors.dimmed(text.rstrip()))
            except Exception:
                pass
        return got

    def do_interact(self, args):
        """interact <sid>  — drop into a shell on a session"""
        sid = args.strip()
        s = self.sessions.get(sid)
        if not s:
            print(colors.bad(f"no such session: {sid}"))
            return
        if not s.alive:
            print(colors.bad(f"session {sid} is dead"))
            return
        print(colors.info(
            f"interacting with {sid}. 'background' returns, '!cmd' runs locally."
        ))

        self._sync_session(s, timeout=4.0)

        for init_cmd in (
            "stty -echo 2>/dev/null",
            "PS1='' PS2=''",
            "set +m 2>/dev/null",
        ):
            s.shell(init_cmd, timeout=0.5)

        self._sync_session(s, timeout=0.5)

        while s.alive:
            try:
                cmd = self._session.prompt(ANSI(colors.session(f"{sid} $ ")))
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                print()
                break

            if cmd.strip() == "background":
                break

            if cmd.startswith("!"):
                local_cmd = cmd[1:].strip()
                if local_cmd:
                    self._run_local(local_cmd)
                continue

            if not cmd.strip():
                continue
            out = s.shell(cmd)
            if not s.alive:
                print(colors.warn("session died during command"))
                break
            if out:
                print(out, end="" if out.endswith("\n") else "\n")

    def do_kill(self, args):
        """kill <sid>  — close a session"""
        sid = args.strip()
        if not sid:
            print(colors.warn("usage: kill <sid>"))
            return
        if sid not in self.sessions:
            print(colors.bad(f"no such session: {sid}"))
            return
        self.sessions.remove(sid)

    def do_reap(self, _):
        """reap  — drop dead sessions"""
        self.sessions.reap()

    def _table(self, headers, rows, indent=2, cellpad=2, show_header=True):
        import re

        headers = list(headers or [])
        n = len(headers) if headers else max((len(r) for r in rows), default=0)
        if n == 0:
            return ""

        norm = []
        for r in rows:
            row = ["" if c is None else str(c) for c in r]
            while len(row) < n:
                row.append("")
            norm.append(row[:n])

        widths = []
        for i in range(n):
            w = 0
            if headers and i < len(headers):
                w = len(colors.strip_ansi(headers[i]))
            for row in norm:
                w = max(w, len(colors.strip_ansi(row[i])))
            widths.append(w)

        pad = " " * cellpad
        ind = " " * indent

        def fmt(val, width):
            visible = len(colors.strip_ansi(val))
            if visible > width:
                return val
            return val + " " * (width - visible)

        lines = []
        if show_header and headers:
            hdr = ind + pad.join(fmt(h, widths[i]) for i, h in enumerate(headers))
            lines.append(colors.heading(hdr))
            sep = ind + pad.join("-" * w for w in widths)
            lines.append(colors.dimmed(sep))
        for row in norm:
            lines.append(ind + pad.join(fmt(row[i], widths[i]) for i in range(n)))
        return "\n".join(lines)

    def do_workspace(self, args):
        """workspace [<name>|add <name>|del <name>|info|reset|clear]  — manage workspaces"""
        parts = args.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else ""
        rest = parts[1].strip() if len(parts) > 1 else ""

        if not sub or sub == "list":
            current = self.db.current_workspace()
            rows = self.db.list_workspaces()
            if not rows:
                print(colors.info("no workspaces — create one with 'workspace add <name>'"))
                return
            print(colors.heading("  Workspaces"))
            print(colors.dimmed("  ----------"))
            for w in rows:
                marker = colors.good("(current)") if w["name"] == current else ""
                print(f"  {w['name'].ljust(24)} {marker}")
            return

        if sub == "clear":
            self.db.set_workspace(None)
            print(colors.info("no active workspace"))
            return

        if sub == "info":
            name = rest or self.db.current_workspace()
            if not name:
                print(colors.warn("no active workspace — specify a name"))
                return
            prev = self.db.current_workspace()
            if not self.db.set_workspace(name):
                print(colors.bad(f"no such workspace: {name}"))
                return
            stats = self.db.stats()
            print(colors.heading(f"workspace: {name}"))
            for k, v in stats.items():
                print(f"  {k.ljust(12)} {v}")
            if prev != name:
                self.db.set_workspace(prev)
            return

        if sub == "add":
            name = rest
            if not name:
                print(colors.warn("usage: workspace add <name>"))
                return
            wid = self.db.create_workspace(name)
            if wid:
                self.db.set_workspace(name)
                print(colors.good(f"workspace created and activated: {name}"))
            return

        if sub == "del":
            name = rest
            if not name:
                print(colors.warn("usage: workspace del <name>"))
                return
            answer = self._session.prompt(
                ANSI(colors.warn(f"delete workspace '{name}' and all its data? [y/N] "))
            )
            if answer.strip().lower() != "y":
                print(colors.info("aborted"))
                return
            try:
                if self.db.delete_workspace(name):
                    print(colors.good(f"workspace deleted: {name}"))
                else:
                    print(colors.bad(f"no such workspace: {name}"))
            except ValueError as e:
                print(colors.bad(str(e)))
            return

        if sub == "reset":
            name = rest or self.db.current_workspace()
            if not name:
                print(colors.warn("no active workspace — specify a name"))
                return
            answer = self._session.prompt(
                ANSI(colors.warn(f"wipe all data in workspace '{name}'? [y/N] "))
            )
            if answer.strip().lower() != "y":
                print(colors.info("aborted"))
                return
            if self.db.reset_workspace(name):
                print(colors.good(f"workspace reset: {name}"))
            else:
                print(colors.bad(f"no such workspace: {name}"))
            return

        if self.db.set_workspace(sub):
            print(colors.good(f"workspace -> {sub}"))
        else:
            print(colors.bad(f"no such workspace: {sub}"))

    def do_hosts(self, args):
        """hosts [add|del|info] [args]  — list/manage hosts in the workspace"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return
        parts = args.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else ""
        rest = parts[1].strip() if len(parts) > 1 else ""

        if not sub or sub == "list":
            rows = self.db.list_hosts()
            if not rows:
                print(colors.info("no hosts in workspace"))
                return
            data = []
            for h in rows:
                data.append([
                    h["address"],
                    h["name"] or ".",
                    h["os"] or ".",
                    h["state"] or ".",
                    self._fmt_ts(h["updated_at"]),
                ])
            print(self._table(
                ["Address", "Name", "OS", "State", "Last Seen"],
                data,
            ))
            print(colors.dimmed(f"  ({len(rows)} host(s))"))
            return

        if sub == "add":
            address = rest
            if not address:
                print(colors.warn("usage: hosts add <address>"))
                return
            self.db.ensure_host(address)
            print(colors.good(f"host added: {address}"))
            return

        if sub == "del":
            address = rest
            if not address:
                print(colors.warn("usage: hosts del <address>"))
                return
            if self.db.delete_host(address):
                print(colors.good(f"host deleted: {address}"))
            else:
                print(colors.bad(f"no such host: {address}"))
            return

        if sub == "info":
            address = rest
            if not address:
                print(colors.warn("usage: hosts info <address>"))
                return
            h = self.db.get_host(address)
            if not h:
                print(colors.bad(f"no such host: {address}"))
                return
            print(colors.heading("Address:   ") + h["address"])
            print(colors.heading("Name:      ") + (h["name"] or "."))
            print(colors.heading("OS:        ") + (h["os"] or "."))
            print(colors.heading("State:     ") + h["state"])
            print(colors.heading("Info:      ") + (h["info"] or "."))
            print(colors.heading("First seen:") + " " + self._fmt_ts(h["created_at"]))
            print(colors.heading("Last seen: ") + self._fmt_ts(h["updated_at"]))
            services = self.db.list_services(address)
            if services:
                print()
                print(colors.heading("Services:"))
                sdata = []
                for s in services:
                    sdata.append([
                        f"{s['port']}/{s['proto']}",
                        s["name"] or ".",
                        s["banner"] or "",
                    ])
                print(self._table([], sdata, indent=4, cellpad=2,
                                  show_header=False))
            return

        print(colors.warn("usage: hosts [add|del|info] [args]"))

    def do_services(self, args):
        """services [<host>|add <host> <port> [name]|del <id>]  — manage services"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return
        parts = args.strip().split(maxsplit=2)
        sub = parts[0].lower() if parts else ""

        if not sub or sub == "list":
            rows = self.db.list_services()
            if not rows:
                print(colors.info("no services in workspace"))
                return
            data = []
            for s in rows:
                data.append([
                    s["address"],
                    str(s["port"]),
                    s["proto"],
                    s["name"] or ".",
                    s["banner"] or "",
                ])
            print(self._table(
                ["Host", "Port", "Proto", "Name", "Banner"],
                data,
            ))
            print(colors.dimmed(f"  ({len(rows)} service(s))"))
            return

        if sub == "add":
            if len(parts) < 3:
                print(colors.warn("usage: services add <host> <port> [name]"))
                return
            host, port, name = parts
            try:
                port = int(port)
            except ValueError:
                print(colors.bad("port must be an integer"))
                return
            self.db.add_service(host, port, name=name)
            print(colors.good(f"service added: {host}:{port}"))
            return

        if sub == "del":
            try:
                sid = int(parts[1])
            except (ValueError, IndexError):
                print(colors.warn("usage: services del <id>"))
                return
            if self.db.delete_service(sid):
                print(colors.good(f"service {sid} deleted"))
            else:
                print(colors.bad(f"no such service: {sid}"))
            return

        rows = self.db.list_services(sub)
        if not rows:
            print(colors.info(f"no services for {sub}"))
            return
        data = []
        for s in rows:
            data.append([
                s["address"],
                str(s["port"]),
                s["proto"],
                s["name"] or ".",
                s["banner"] or "",
            ])
        print(self._table(
            ["Host", "Port", "Proto", "Name", "Banner"],
            data,
        ))

    def do_vulns(self, args):
        """vulns [<host>|del <id>]  — list/delete recorded vulnerabilities"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return
        parts = args.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else ""

        if sub == "del":
            try:
                vid = int(parts[1])
            except (ValueError, IndexError):
                print(colors.warn("usage: vulns del <id>"))
                return
            if self.db.delete_vuln(vid):
                print(colors.good(f"vuln {vid} deleted"))
            else:
                print(colors.bad(f"no such vuln: {vid}"))
            return

        host = sub or None
        rows = self.db.list_vulns(host)
        if not rows:
            print(colors.info("no vulns recorded"))
            return
        data = []
        for v in rows:
            sev = v["severity"] or "unknown"
            sev_col = colors.bad(sev) if sev in ("high", "critical") else colors.warn(sev) if sev == "medium" else colors.dimmed(sev)
            data.append([
                str(v["id"]),
                v["address"] or ".",
                sev_col,
                v["name"],
                v["module"],
            ])
        print(self._table(
            ["ID", "Host", "Sev", "Name", "Module"],
            data,
        ))
        print(colors.dimmed(f"  ({len(rows)} vuln(s))"))

    def do_creds(self, args):
        """creds [del <id>]  — list/delete credentials"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return
        parts = args.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else ""

        if sub == "del":
            try:
                cid = int(parts[1])
            except (ValueError, IndexError):
                print(colors.warn("usage: creds del <id>"))
                return
            if self.db.delete_cred(cid):
                print(colors.good(f"cred {cid} deleted"))
            else:
                print(colors.bad(f"no such cred: {cid}"))
            return

        rows = self.db.list_creds()
        if not rows:
            print(colors.info("no creds recorded"))
            return
        data = []
        for c in rows:
            secret = c["secret"]
            if len(secret) > 20:
                secret = secret[:17] + "..."
            data.append([
                str(c["id"]),
                c["address"] or ".",
                c["username"] or ".",
                c["kind"],
                secret,
            ])
        print(self._table(
            ["ID", "Host", "User", "Kind", "Secret"],
            data,
        ))

    def do_notes(self, args):
        """notes [add <data> | del <id>]  — list/add/delete notes"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return
        parts = args.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else ""

        if sub == "add":
            data = parts[1].strip() if len(parts) > 1 else ""
            if not data:
                print(colors.warn("usage: notes add <text>"))
                return
            self.db.add_note(data)
            print(colors.good("note added"))
            return

        if sub == "del":
            try:
                nid = int(parts[1])
            except (ValueError, IndexError):
                print(colors.warn("usage: notes del <id>"))
                return
            if self.db.delete_note(nid):
                print(colors.good(f"note {nid} deleted"))
            else:
                print(colors.bad(f"no such note: {nid}"))
            return

        rows = self.db.list_notes()
        if not rows:
            print(colors.info("no notes"))
            return
        data = []
        for n in rows:
            data.append([
                colors.session(str(n["id"]).rjust(4)),
                self._fmt_ts(n["created_at"]),
                n["data"],
            ])
        print(self._table([], data, indent=2, cellpad=2, show_header=False))

    def do_loot(self, args):
        """loot [del <id>]  — list/delete loot"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return
        parts = args.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else ""

        if sub == "del":
            try:
                lid = int(parts[1])
            except (ValueError, IndexError):
                print(colors.warn("usage: loot del <id>"))
                return
            if self.db.delete_loot(lid):
                print(colors.good(f"loot {lid} deleted"))
            else:
                print(colors.bad(f"no such loot: {lid}"))
            return

        rows = self.db.list_loot()
        if not rows:
            print(colors.info("no loot"))
            return
        data = []
        for l in rows:
            data.append([
                str(l["id"]),
                l["address"] or ".",
                l["kind"] or ".",
                str(l["size"]),
                l["path"] or "",
            ])
        print(self._table(
            ["ID", "Host", "Kind", "Size", "Path"],
            data,
        ))

    def do_events(self, args):
        """events  — list recent workspace events"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return
        limit = 100
        if args.strip():
            try:
                limit = int(args.strip())
            except ValueError:
                pass
        rows = self.db.list_events(limit=limit)
        if not rows:
            print(colors.info("no events"))
            return
        data = []
        for e in rows:
            data.append([
                self._fmt_ts(e["created_at"]),
                e["address"] or ".",
                e["message"],
            ])
        print(self._table([], data, indent=2, cellpad=2, show_header=False))

    def do_db(self, args):
        """db [status|stats|reset]  — database operations"""
        sub = args.strip().lower()

        if not sub or sub == "status":
            print(colors.heading("database status"))
            print(f"  path:      {self.db.path}")
            ws = self.db.current_workspace()
            print(f"  workspace: {ws if ws else '(none)'}")
            print(f"  file size: {self.db.size_bytes()} bytes")
            return

        if sub == "stats":
            ws = self.db.current_workspace()
            if not ws:
                print(colors.warn("no active workspace — run 'workspace <name>' first"))
                return
            stats = self.db.stats()
            print(colors.heading(f"workspace: {ws}"))
            for k, v in stats.items():
                print(f"  {k.ljust(12)} {v}")
            return

        if sub == "reset":
            ws = self.db.current_workspace()
            if not ws:
                print(colors.warn("no active workspace — run 'workspace <name>' first"))
                return
            answer = self._session.prompt(
                ANSI(colors.warn("wipe ALL data in current workspace? [y/N] "))
            )
            if answer.strip().lower() != "y":
                print(colors.info("aborted"))
                return
            self.db.reset_workspace(ws)
            print(colors.good("workspace reset"))
            return

        print(colors.warn("usage: db [status|stats|reset]"))

    def _import_preview(self, parsed):
        print()
        print(colors.heading("  imported hosts:"))
        data = []
        for h in parsed["hosts"][:20]:
            svc_count = len(h.get("services") or [])
            data.append([
                colors.good(h["address"]),
                colors.dimmed(h.get("hostname") or "") if h.get("hostname") else "",
                colors.session(h.get("os") or "") if h.get("os") else "",
                colors.dimmed(f"({svc_count} service(s))") if svc_count else "",
            ])
        print(self._table([], data, indent=4, cellpad=2, show_header=False))
        if len(parsed["hosts"]) > 20:
            print(colors.dimmed(f"    ... {len(parsed['hosts']) - 20} more"))

    def do_db_nmap(self, args):
        """db_nmap <nmap args>  — run nmap live and import results into the active workspace"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return

        nmap_args = args.strip()
        if not nmap_args:
            print(colors.warn("usage: db_nmap <nmap args>"))
            print(colors.dimmed("  e.g. db_nmap -sV -O 192.168.1.0/24"))
            print(colors.dimmed("  output flags (-oX, -oN, -oG, -oA) are stripped"))
            return

        from core.nmap_import import (
            nmap_available, strip_output_flags, run_nmap,
            parse_nmap_xml, import_to_db,
        )

        if not nmap_available():
            print(colors.bad("nmap not found on PATH"))
            return

        cleaned = strip_output_flags(nmap_args)
        print(colors.info(f"db_nmap: nmap {cleaned}"))
        print(colors.dimmed("  nmap output will stream below; results import when it finishes"))
        print()

        try:
            xml = run_nmap(cleaned, timeout=3600.0)
        except KeyboardInterrupt:
            print()
            print(colors.warn("db_nmap: interrupted"))
            return
        except Exception as e:
            print(colors.bad(f"nmap failed: {e}"))
            return

        print()
        try:
            parsed = parse_nmap_xml(xml)
        except Exception as e:
            print(colors.bad(f"parse failed: {e}"))
            return

        if parsed.get("repaired"):
            print(colors.warn(
                "nmap output was truncated — recovered host data from partial XML"
            ))

        print(colors.info(
            f"  nmap completed: {len(parsed['hosts'])} host(s) up, "
            f"{parsed['runstats'].get('elapsed', 0):.1f}s"
        ))

        try:
            counts = import_to_db(self.db, parsed)
        except Exception as e:
            print(colors.bad(f"import failed: {e}"))
            return

        ws = self.db.current_workspace()
        print(colors.good(
            f"db_nmap: imported into workspace '{ws}': "
            f"{counts['hosts']} host(s), {counts['services']} service(s), "
            f"{counts['notes']} note(s)"
        ))

        if parsed["hosts"]:
            self._import_preview(parsed)

    def do_db_import(self, args):
        """db_import <file.xml>  — import nmap XML results into the active workspace"""
        if not self.db.current_workspace_id():
            print(colors.warn("no active workspace — run 'workspace <name>' first"))
            return

        path = args.strip()
        if not path:
            print(colors.warn("usage: db_import <file.xml>"))
            print(colors.dimmed("  e.g. db_import scan.xml"))
            return

        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.join(self._local_cwd, path)
        path = os.path.normpath(path)

        if not os.path.isfile(path):
            print(colors.bad(f"file not found: {path}"))
            return

        from core.nmap_import import parse_nmap_xml, import_to_db

        print(colors.info(f"db_import: parsing {path}"))
        try:
            with open(path, "r", errors="replace") as f:
                xml = f.read()
        except OSError as e:
            print(colors.bad(f"could not read file: {e}"))
            return

        try:
            parsed = parse_nmap_xml(xml)
        except Exception as e:
            print(colors.bad(f"parse failed: {e}"))
            return

        if parsed.get("repaired"):
            print(colors.warn(
                "file was truncated — recovered host data from partial XML"
            ))

        total_services = sum(len(h.get("services") or []) for h in parsed["hosts"])
        print(colors.info(
            f"  parsed: {len(parsed['hosts'])} host(s) up, {total_services} service(s)"
        ))

        try:
            counts = import_to_db(self.db, parsed)
        except Exception as e:
            print(colors.bad(f"import failed: {e}"))
            return

        ws = self.db.current_workspace()
        print(colors.good(
            f"db_import: imported into workspace '{ws}': "
            f"{counts['hosts']} host(s), {counts['services']} service(s), "
            f"{counts['notes']} note(s)"
        ))

        if parsed["hosts"]:
            self._import_preview(parsed)

    @staticmethod
    def _fmt_ts(ts):
        from datetime import datetime
        if not ts:
            return "."
        try:
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
        except (ValueError, OSError):
            return str(ts)

    def _rank_color(self, rank):
        r = rank.lower()
        if r == "excellent":
            return colors.wrap("good")
        if r == "great":
            return colors.wrap("session")
        if r == "good":
            return colors.wrap("info")
        if r in ("normal", "average"):
            return lambda s: s
        if r == "low":
            return colors.wrap("dim")
        if r == "manual":
            return colors.wrap("warn")
        return lambda s: s

    def _print_module_table(self, rows):
        if not rows:
            print(colors.info("no modules"))
            return

        w_idx = max(len(str(len(rows))), 1)
        w_path = max(len(r["path"]) for r in rows)
        w_path = min(max(w_path, 40), 70)
        w_date = 10
        w_rank = 9
        w_chk = 3

        header = (
            f"  {'#'.ljust(w_idx)}   "
            f"{'Module'.ljust(w_path)}  "
            f"{'Date'.ljust(w_date)}  "
            f"{'Rank'.ljust(w_rank)}  "
            f"{'Chk'.ljust(w_chk)}  "
            f"Description"
        )
        print(colors.heading(header))
        sep = (
            f"  {'-'*w_idx}   "
            f"{'-'*w_path}  "
            f"{'-'*w_date}  "
            f"{'-'*w_rank}  "
            f"{'-'*w_chk}  "
            f"{'-'*11}"
        )
        print(colors.dimmed(sep))

        for i, r in enumerate(rows, 1):
            path = r["path"]
            if len(path) > w_path:
                path = path[:w_path - 3] + "..."
            date = r["disclosed"] or "."
            rank = r["rank"]
            chk = "Yes" if r["check"] else "No"
            desc = r["name"] or r["description"]
            rank_col = self._rank_color(rank)
            print(
                f"  {str(i).ljust(w_idx)}   "
                f"{path.ljust(w_path)}  "
                f"{date.ljust(w_date)}  "
                f"{rank_col(rank.ljust(w_rank))}  "
                f"{chk.ljust(w_chk)}  "
                f"{desc}"
            )

    def _print_payload_table(self):
        from core.payloads import REGISTRY
        if not REGISTRY:
            print(colors.info("no payloads registered"))
            return
        names = sorted(REGISTRY)
        w_name = max(len(n) for n in names)
        print(colors.heading(f"  {'Name'.ljust(w_name)}  Kind"))
        print(colors.dimmed(f"  {'-'*w_name}  ----"))
        for name in names:
            print(f"  {name.ljust(w_name)}  reverse shell")

    def _extract_cves(self, text):
        import re
        return [m.upper() for m in re.findall(r"CVE-\d{4}-\d+", text, re.I)]

    def _search_by_cves(self, cves):
        print(colors.info("searching " + str(len(cves)) + " CVE(s)..."))
        found = {}
        missing = []

        for cve in cves:
            matched = []
            for path in self.modules.list():
                meta = self.modules.metadata(path)
                blob = " ".join([
                    path,
                    meta["name"],
                    meta["description"],
                    " ".join(meta.get("references") or []),
                ]).upper()
                if cve.upper() in blob:
                    matched.append(meta)
            if matched:
                found[cve] = matched
            else:
                missing.append(cve)

        if not found:
            print(colors.info("no modules matched any of the CVEs"))
            if missing:
                print(colors.dimmed("  missing: " + ", ".join(missing)))
            return

        all_rows = []
        for cve, metas in found.items():
            print()
            print(colors.heading(cve))
            for meta in metas:
                print("  " + colors.session(meta["path"]))
                print("    " + colors.dimmed(meta["name"]))
                all_rows.append(meta)

        print()
        total = len(all_rows)
        print(colors.dimmed("  " + str(total) + " module(s) across " + str(len(found)) + " CVE(s)"))
        if missing:
            print(colors.dimmed("  no module for: " + ", ".join(missing)))

        self.last_search = all_rows

    def _search_from_file(self, path):
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.join(self._local_cwd, path)
        if not os.path.isfile(path):
            print(colors.bad("file not found: " + path))
            return

        try:
            with open(path) as f:
                content = f.read()
        except OSError as e:
            print(colors.bad("could not read file: " + str(e)))
            return

        cves = self._extract_cves(content)
        if not cves:
            print(colors.warn("no CVE IDs found in " + path))
            return

        cves = list(dict.fromkeys(cves))
        print(colors.info("loaded " + str(len(cves)) + " unique CVE(s) from " + path))
        self._search_by_cves(cves)

    def do_search(self, args):
        """search <term|CVE|file:path>  — search modules by keyword, CVE ID, or file"""
        term = args.strip()
        if not term:
            print(colors.warn("usage: search <term>"))
            print(colors.dimmed("  search redis              — text match"))
            print(colors.dimmed("  search CVE-2022-0543      — CVE lookup"))
            print(colors.dimmed("  search CVE-2022-0543,CVE-2017-12615"))
            print(colors.dimmed("  search file:cves.txt      — bulk CVE lookup"))
            return

        if term.startswith("file:"):
            self._search_from_file(term[len("file:"):].strip())
            return

        cves = self._extract_cves(term)
        if cves and len(term.split()) == 1:
            self._search_by_cves(cves)
            return

        hits = self.modules.search_detailed(term)
        self.last_search = hits
        if not hits:
            print(colors.info("no matches"))
            return
        self._print_module_table(hits)
        print(colors.dimmed(f"  ({len(hits)} match(es). Use 'use N' to select by number.)"))

    def do_show(self, args):
        """show modules | options | info | globals | themes | payloads | spool | workspaces | hosts | services | vulns | creds | notes | loot | events"""
        what = args.strip().split()[0] if args.strip() else ""
        if what == "modules":
            rows = [self.modules.metadata(p) for p in self.modules.list()]
            self._print_module_table(rows)
        elif what == "payloads":
            self._print_payload_table()
        elif what == "options":
            if not self.active_module:
                print(colors.bad("no module selected"))
                return
            self.active_module.show_options()
        elif what == "info":
            self.do_info("")
        elif what == "globals":
            if not self.global_options:
                print(colors.info("no global options set"))
                return
            for k, v in self.global_options.items():
                print(f"  {k} => {v}")
        elif what == "themes":
            current = colors.current_theme()
            for t in colors.list_themes():
                marker = colors.good("(current)") if t == current else ""
                print(f"  {t.ljust(16)} {colors.theme_preview(t)} {marker}")
        elif what == "spool":
            if self._spool_file:
                print(colors.info("spooling to: " + self._spool_file))
            else:
                print(colors.info("spooling: off"))
        elif what == "workspaces":
            self.do_workspace("")
        elif what == "hosts":
            self.do_hosts("")
        elif what == "services":
            self.do_services("")
        elif what == "vulns":
            self.do_vulns("")
        elif what == "creds":
            self.do_creds("")
        elif what == "notes":
            self.do_notes("")
        elif what == "loot":
            self.do_loot("")
        elif what == "events":
            self.do_events("")
        else:
            print(colors.warn(
                "usage: show modules | options | info | globals | themes | "
                "payloads | spool | workspaces | hosts | services | vulns | "
                "creds | notes | loot | events"
            ))

    def do_options(self, _):
        """options  — alias for 'show options'"""
        self.do_show("options")

    def do_info(self, args):
        """info [N|path]  — show module details"""
        target = None
        arg = args.strip()
        if arg:
            if arg.isdigit():
                idx = int(arg) - 1
                if not (0 <= idx < len(self.last_search)):
                    print(colors.bad(f"no search result #{arg}"))
                    return
                target = self.last_search[idx]
            else:
                try:
                    target = self.modules.metadata(arg)
                except KeyError as e:
                    print(colors.bad(str(e)))
                    return
        elif self.active_module:
            target = self.modules.metadata(self.active_path)
        else:
            print(colors.bad("no module selected"))
            return

        rank_col = self._rank_color(target["rank"])
        print(colors.heading("Name:        ") + target["name"])
        print(colors.heading("Module:      ") + target["path"])
        print(colors.heading("Rank:        ") + rank_col(target["rank"]))
        if target["disclosed"]:
            print(colors.heading("Disclosed:   ") + target["disclosed"])
        print(colors.heading("Check:       ") + ("Yes" if target["check"] else "No"))
        if target["author"]:
            print(colors.heading("Author:      ") + target["author"])
        if target["references"]:
            print(colors.heading("References:  ") + ", ".join(target["references"]))
        print()
        print(colors.heading("Description:"))
        for line in self._wrap(target["description"], 78):
            print("  " + line)

    @staticmethod
    def _wrap(text, width):
        words = text.split()
        lines, cur = [], ""
        for w in words:
            if len(cur) + len(w) + 1 > width:
                lines.append(cur)
                cur = w
            else:
                cur = f"{cur} {w}".strip()
        if cur:
            lines.append(cur)
        return lines or [""]

    def do_use(self, args):
        """use <N|module/path>  — select a module"""
        arg = args.strip()
        if not arg:
            print(colors.warn("usage: use <N|module/path>"))
            return

        path = arg
        if arg.isdigit():
            idx = int(arg) - 1
            if self.last_search:
                source = self.last_search
                source_label = "search result"
            else:
                source = [self.modules.metadata(p) for p in self.modules.list()]
                source_label = "module"
            if not (0 <= idx < len(source)):
                print(colors.bad(
                    f"{source_label} #{arg} out of range (have {len(source)})"
                ))
                return
            path = source[idx]["path"]

        try:
            self.active_module = self.modules.get(path)
        except KeyError as e:
            print(colors.bad(str(e)))
            return
        self.active_module.framework = self
        self.active_path = path
        for name, value in self.global_options.items():
            if name in self.active_module.options:
                try:
                    self.active_module.set_option(name, value)
                except Exception:
                    pass
        print(colors.info(f"using {path}"))

    def do_back(self, _):
        """back  — deselect the current module"""
        self.active_module = None
        self.active_path = None

    def do_set(self, args):
        """set <OPTION> <value>  — set a module option"""
        if not self.active_module:
            print(colors.bad("no module selected"))
            return
        parts = args.split(maxsplit=1)
        if len(parts) != 2:
            print(colors.warn("usage: set <OPTION> <value>"))
            return
        name, value = parts
        try:
            self.active_module.set_option(name.upper(), value)
        except KeyError as e:
            print(colors.bad(str(e)))
            return
        except (TypeError, ValueError) as e:
            print(colors.bad(f"bad value for {name.upper()}: {e}"))
            return
        print(colors.good(f"{name.upper()} => {value}"))

    def do_unset(self, args):
        """unset <OPTION>  — clear a module option"""
        if not self.active_module:
            print(colors.bad("no module selected"))
            return
        name = args.strip().upper()
        if name not in self.active_module.options:
            print(colors.bad(f"unknown option: {name}"))
            return
        self.active_module.options[name] = None
        print(colors.info(f"{name} unset"))

    def do_setg(self, args):
        """setg <OPTION> <value>  — set a global option (persists across runs)"""
        parts = args.split(maxsplit=1)
        if len(parts) != 2:
            print(colors.warn("usage: setg <OPTION> <value>"))
            return
        name, value = parts
        self.global_options[name.upper()] = value
        self._save_globals()
        if self.active_module and name.upper() in self.active_module.options:
            try:
                self.active_module.set_option(name.upper(), value)
            except Exception:
                pass
        print(colors.good(f"global {name.upper()} => {value}"))

    def do_unsetg(self, args):
        """unsetg <OPTION>  — clear a global option"""
        name = args.strip().upper()
        if name not in self.global_options:
            print(colors.bad(f"no such global option: {name}"))
            return
        del self.global_options[name]
        self._save_globals()
        print(colors.info(f"global {name} cleared"))

    def do_check(self, _):
        """check  — run the active module's check()"""
        if not self.active_module:
            print(colors.bad("no module selected"))
            return
        missing = self.active_module.required_missing()
        if missing:
            print(colors.bad(f"missing required options: {', '.join(missing)}"))
            return
        try:
            result = self.active_module.check()
        except Exception as e:
            print(colors.bad(f"check failed: {e}"))
            return
        from core.check import CheckResult
        print(colors.info(f"check -> {CheckResult.colorize(result)}"))

        if self.db and self.db.current_workspace_id() and result == CheckResult.VULNERABLE:
            targets = self.active_module.resolve_targets()
            name = self.active_module.NAME or self.active_path
            for t in targets:
                self.db.ensure_host(t, state="up")
                self.db.add_vuln(
                    name=name,
                    module=self.active_path,
                    host_address=t,
                    severity="unknown",
                    info="check() returned vulnerable",
                )
            if not targets:
                self.db.add_vuln(
                    name=name,
                    module=self.active_path,
                    severity="unknown",
                    info="check() returned vulnerable (no target recorded)",
                )
            print(colors.dimmed(
                f"  (vuln recorded in workspace '{self.db.current_workspace()}')"
            ))

    def do_run(self, args):
        """run [target]  — execute the active module"""
        self._run_active(args)

    def do_exploit(self, args):
        """exploit [target]  — alias for run"""
        self._run_active(args)

    def _run_active(self, args=""):
        if not self.active_module:
            print(colors.bad("no module selected"))
            return
        target = args.strip()
        if target:
            if "RHOSTS" in self.active_module.options:
                try:
                    self.active_module.set_option("RHOSTS", target)
                except (TypeError, ValueError) as e:
                    print(colors.bad(f"bad target override: {e}"))
                    return
                print(colors.good(f"RHOSTS => {target}"))
            elif "RHOST" in self.active_module.options:
                try:
                    self.active_module.set_option("RHOST", target)
                except (TypeError, ValueError) as e:
                    print(colors.bad(f"bad RHOST override: {e}"))
                    return
                print(colors.good(f"RHOST => {target}"))

        try:
            self.active_module.run()
        except ValueError as e:
            print(colors.bad(str(e)))
        except KeyboardInterrupt:
            print(colors.warn("interrupted"))
        except Exception as e:
            print(colors.bad(f"run failed: {e}"))

    def do_resource(self, args):
        """resource <file.rc>  — execute commands from an rc file"""
        path = args.strip()
        if not path:
            print(colors.warn("usage: resource <file.rc>"))
            return
        from core.rc import execute_rc
        try:
            execute_rc(self, path, echo=True)
        except FileNotFoundError as e:
            print(colors.bad(str(e)))
        except Exception as e:
            print(colors.bad(f"resource failed: {type(e).__name__}: {e}"))

    def do_source(self, args):
        """source [file]  — load KEY=VALUE options into the active module"""
        if not self.active_module:
            print(colors.bad("no module selected"))
            return
        path = args.strip()
        if not path:
            current = self.active_module.options.get("SOURCE")
            print(colors.info(f"SOURCE = {current!r}"))
            return
        try:
            self.active_module.set_option("SOURCE", path)
        except (TypeError, ValueError) as e:
            print(colors.bad(f"could not set SOURCE: {e}"))
            return
        try:
            self.active_module.load_source()
        except (FileNotFoundError, ValueError) as e:
            print(colors.bad(str(e)))
            return
        print(colors.good(f"SOURCE => {path}"))

    def do_spool(self, args):
        """spool [file]  — log all console output to a file (no arg = stop)"""
        path = args.strip()
        if not path:
            if self._spool_file:
                print(colors.info("spool stopped: " + self._spool_file))
                self._spool_file = None
            else:
                print(colors.info("spooling is off"))
            return
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.join(self._local_cwd, path)
        try:
            with open(path, "a") as f:
                f.write("# metis spool started\n")
        except OSError as e:
            print(colors.bad("could not open spool file: " + str(e)))
            return
        self._spool_file = path
        print(colors.good("spooling to: " + path))

    def do_history(self, args):
        """history [n]  — show last N commands (default 20)"""
        n = 20
        if args.strip():
            try:
                n = int(args.strip())
            except ValueError:
                print(colors.warn("usage: history [n]"))
                return
        history_path = os.path.expanduser("~/.metis_history")
        if not os.path.isfile(history_path):
            print(colors.info("no history yet"))
            return
        try:
            with open(history_path) as f:
                lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        except OSError as e:
            print(colors.bad(str(e)))
            return
        total = len(lines)
        start = max(0, total - n)
        for i, line in enumerate(lines[start:], start + 1):
            print(f"  {str(i).rjust(4)}  {line}")

    def do_theme(self, args):
        """theme [name]  — list themes or switch to one"""
        name = args.strip()
        if not name:
            current = colors.current_theme()
            for t in colors.list_themes():
                marker = colors.good("(current)") if t == current else ""
                print(f"  {t.ljust(16)} {colors.theme_preview(t)} {marker}")
            return
        if not colors.set_theme(name):
            print(colors.bad(f"no such theme: {name}"))
            print(colors.dimmed(f"  available: {', '.join(colors.list_themes())}"))
            return
        print(colors.good(f"theme -> {name}"))
        print(f"  {colors.theme_preview(name)}")

    def do_gradient(self, args):
        """gradient [<codes...> | reset | list | preview | preset <name> | save <name>]"""
        from core import colors as C
        from core import themes as themes_mod

        parts = args.strip().split()
        theme_name = C.current_theme()
        palette = themes_mod.THEMES.setdefault(theme_name, {})

        if not parts:
            current = C.gradient_stops()
            default = themes_mod.THEMES.get(theme_name, {}).get("bar_gradient")
            print(C.info(f"theme:   {theme_name}"))
            print(C.info(f"current: {current}"))
            if default and default != current:
                print(C.dimmed(f"default: {default}"))
            print()
            print(self._gradient_preview(current))
            print()
            print(C.dimmed("  presets: " + ", ".join(sorted(GRADIENT_PRESETS))))
            return

        sub = parts[0].lower()

        if sub == "reset":
            if "bar_gradient" in palette:
                del palette["bar_gradient"]
                print(C.good(f"gradient reset for theme {theme_name!r}"))
            else:
                print(C.info(f"theme {theme_name!r} had no override"))
            return

        if sub == "list":
            print(C.heading("  Theme            Gradient"))
            print(C.dimmed("  -----            --------"))
            for name in C.list_themes():
                stops = themes_mod.THEMES.get(name, {}).get("bar_gradient") or [51, 45, 39, 135, 171, 201]
                marker = C.good(" (current)") if name == theme_name else ""
                print(f"  {name.ljust(16)} {stops}{marker}")
            return

        if sub == "preview":
            print(self._gradient_preview(C.gradient_stops()))
            return

        if sub == "preset":
            if len(parts) < 2:
                print(C.warn("usage: gradient preset <name>"))
                print(C.dimmed("  available: " + ", ".join(sorted(GRADIENT_PRESETS))))
                return
            preset_name = parts[1].lower()
            stops = GRADIENT_PRESETS.get(preset_name)
            if not stops:
                print(C.bad(f"no such preset: {preset_name}"))
                print(C.dimmed("  available: " + ", ".join(sorted(GRADIENT_PRESETS))))
                return
            palette["bar_gradient"] = list(stops)
            print(C.good(f"bar_gradient for {theme_name!r} = preset {preset_name!r} {stops}"))
            print()
            print(self._gradient_preview(list(stops)))
            return

        if sub == "save":
            if len(parts) < 2:
                print(C.warn("usage: gradient save <new-theme-name>"))
                return
            new_name = parts[1]
            if new_name in themes_mod.THEMES:
                print(C.bad(f"theme already exists: {new_name}"))
                return
            clone = dict(themes_mod.THEMES[theme_name])
            themes_mod.THEMES[new_name] = clone
            print(C.good(f"theme {new_name!r} created"))
            return

        try:
            codes = [int(p) for p in parts]
        except ValueError:
            print(C.bad("stops must be integers 0-255"))
            return
        if not all(0 <= c <= 255 for c in codes):
            print(C.bad("stops must be in 0-255"))
            return
        if len(codes) < 2:
            print(C.warn("need at least 2 stops for a gradient"))
            return
        palette["bar_gradient"] = codes
        print(C.good(f"bar_gradient for {theme_name!r} = {codes}"))
        print()
        print(self._gradient_preview(codes))

    def _gradient_preview(self, stops):
        width = 40
        cells = []
        for i in range(width):
            pos = i / max(width - 1, 1)
            idx = pos * (len(stops) - 1)
            lo = int(idx)
            if lo >= len(stops) - 1:
                code = stops[-1]
            else:
                frac = idx - lo
                code = stops[lo] if frac < 0.5 else stops[lo + 1]
            cells.append(f"\033[38;5;{code}m█\033[0m")
        return f"  preview ({len(stops)} stops): " + "".join(cells)

    def do_help(self, args):
        """help [command]  — show help"""
        if args.strip():
            cmd = args.strip()
            h = getattr(self, f"do_{cmd}", None)
            if not h:
                print(colors.bad(f"no such command: {cmd}"))
                return
            doc = (h.__doc__ or "").strip().splitlines()
            summary = doc[0] if doc else ""
            if summary.lower().startswith(cmd.lower()):
                summary = summary[len(cmd):].lstrip(" —-")
            print(f"  {colors.session(cmd.ljust(14))} {summary}")
            return
        width = 14
        for name in sorted(n for n in dir(self) if n.startswith("do_")):
            cmd = name[3:]
            doc = (getattr(self, name).__doc__ or "").strip().splitlines()
            summary = doc[0] if doc else ""
            if summary.lower().startswith(cmd.lower()):
                summary = summary[len(cmd):].lstrip(" —-")
            print(f"  {colors.session(cmd.ljust(width))} {summary}")
        print()
        print(colors.dimmed("  tab completes commands, module paths, session IDs, options, workspaces"))
        print(colors.dimmed("  any unrecognised command is passed to your local shell"))

    def do_clear(self, _):
        """clear  — clear the screen"""
        print("\033[2J\033[H", end="", flush=True)

    def do_exit(self, _):
        """exit  — shut down the framework"""
        self.running = False

    def do_quit(self, _):
        """quit  — alias for exit"""
        self.running = False

    def dispatch(self, line):
        if not line.strip():
            return

        self._spool("metis > " + line)

        if line.startswith("!"):
            cmd = line[1:].strip()
            if cmd:
                self._run_local(cmd)
            return

        cmd, _, args = line.partition(" ")
        handler = getattr(self, f"do_{cmd}", None)
        if handler:
            try:
                handler(args)
            except KeyboardInterrupt:
                print(colors.warn("interrupted"))
            except BrokenPipeError:
                print(colors.warn("broken pipe — command aborted"))
            except Exception as e:
                print(colors.bad(f"command error: {type(e).__name__}: {e}"))
            return

        self._run_local(line)

    def run(self):
        print(colors.bold(colors.cyan(self.BANNER)))
        print()
        self._check_update_silent()
        try:
            while self.running:
                try:
                    line = self._session.prompt(ANSI(self.prompt()))
                except KeyboardInterrupt:
                    continue
                except EOFError:
                    print()
                    break
                self.dispatch(line)
        finally:
            for h in self.handlers:
                h.stop()
            self.sessions.close_all()
