import os
import shlex
import subprocess
import sys

from core import colors
from core.module_manager import ModuleManager
from core.session_manager import SessionManager
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


class Console:
    BASE_PROMPT = "metis"
    VERSION = "1.0.0"
    REPO = "K3ysTr0K3R/METIS"
    BANNER = (
        "███╗   ███╗███████╗████████╗██╗███████╗\n"
        "████╗ ████║██╔════╝╚══██╔══╝██║██╔════╝\n"
        "██╔████╔██║█████╗     ██║   ██║███████╗\n"
        "██║╚██╔╝██║██╔══╝     ██║   ██║╚════██║\n"
        "██║ ╚═╝ ██║███████╗   ██║   ██║███████║\n"
        "╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝╚══════╝\n"
        "K3ysTr0K3R                    v1.0.0\n"
        "\n"
        "Modular Exploitation & Threat Intelligence System\n"
    )

    def __init__(self):
        self.sessions = SessionManager()
        self.modules = ModuleManager(root="modules")
        self.handlers = []
        self.active_module = None
        self.active_path = None
        self.global_options = {}
        self.last_search = []
        self.running = True
        self._local_cwd = os.getcwd()
        self._skip_update = "--no-update-check" in sys.argv

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
        body = data.get("body") or ""
        if body:
            first_line = body.splitlines()[0] if body.splitlines() else ""
            print(colors.dimmed("  notes:   " + first_line))

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

        base = self.BASE_PROMPT
        if self.active_path:
            category, _, rest = self.active_path.partition("/")
            src = ""
            if self.active_module and self.active_module.options.get("SOURCE"):
                src = colors.good(" [src]")
            user = user_color(base)
            cat = cat_color(category)
            rest_padded = path_color(f"({rest})") if rest else ""
            return f"{user} {cat}{rest_padded}{src} > "
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
        """shell  — drop into an interactive local shell (exit to return)"""
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
        """exec <cmd>  — run a local shell command (explicit form)"""
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
        """connect <host> <port>  — connect to a bind shell and register a session"""
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
            print(colors.warn("usage: kill_handler <index>  (see 'handlers')"))
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
                cmd = input(colors.session(f"{sid} $ "))
            except (EOFError, KeyboardInterrupt):
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

    def do_search(self, args):
        """search <term>  — find modules by name or description; use N to select"""
        term = args.strip()
        if not term:
            print(colors.warn("usage: search <term>"))
            return
        hits = self.modules.search_detailed(term)
        self.last_search = hits
        if not hits:
            print(colors.info("no matches"))
            return
        self._print_module_table(hits)
        print(colors.dimmed(f"  ({len(hits)} match(es). Use 'use N' to select by number.)"))

    def do_show(self, args):
        """show modules | options | info | globals | themes | payloads"""
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
        else:
            print(colors.warn(
                "usage: show modules | options | info | globals | themes | payloads"
            ))

    def do_options(self, _):
        """options  — alias for 'show options'"""
        self.do_show("options")

    def do_info(self, args):
        """info [N|path]  — show details of active module, a search result, or a path"""
        target = None
        arg = args.strip()
        if arg:
            if arg.isdigit():
                idx = int(arg) - 1
                if not (0 <= idx < len(self.last_search)):
                    print(colors.bad(f"no search result #{arg} — run search first"))
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
            print(colors.bad("no module selected — pass a path or search first"))
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
        """use <N|module/path>  — select a module by search index or path"""
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
        """setg <OPTION> <value>  — set a global option applied to all modules"""
        parts = args.split(maxsplit=1)
        if len(parts) != 2:
            print(colors.warn("usage: setg <OPTION> <value>"))
            return
        name, value = parts
        self.global_options[name.upper()] = value
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

    def do_run(self, args):
        """run [target]  — execute the active module (optional target override)"""
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
        """help [command]  — show help for a command or all commands"""
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
        print(colors.dimmed("  any unrecognised command is passed to your local shell"))
        print(colors.dimmed("  e.g.  id   nmap -sV 10.0.0.1   git status   cat /etc/hosts"))

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
                    line = input(self.prompt())
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                self.dispatch(line)
        finally:
            for h in self.handlers:
                h.stop()
            self.sessions.close_all()
