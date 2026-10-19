import os
from core import colors
from core.rc import parse_source_file
from core.targets import parse_targets

def to_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).lower() in ("1", "true", "yes", "on", "y")

class Option:
    def __init__(self, name, default=None, required=False, description="", type=str):
        self.name = name
        self.default = default
        self.required = required
        self.description = description
        self.type = type

class Module:
    NAME = ""
    DESCRIPTION = ""
    AUTHOR = ""
    REFERENCES = []
    RANK = "normal"
    DISCLOSED = ""
    CHECK = False

    OPTIONS: list[Option] = []

    def __init__(self):
        self.options = {opt.name: opt.default for opt in self.OPTIONS}
        self._opts_meta = {opt.name: opt for opt in self.OPTIONS}

        if "AUTOCHECK" not in self.options:
            self._opts_meta["AUTOCHECK"] = Option(
                "AUTOCHECK", default=True, type=to_bool,
                description="run check() before exploit()",
            )
            self.options["AUTOCHECK"] = True

        if "SOURCE" not in self.options:
            self._opts_meta["SOURCE"] = Option(
                "SOURCE", default=None,
                description="path to KEY=VALUE file to load into options",
            )
            self.options["SOURCE"] = None

        if "RHOSTS" not in self.options and "RHOST" not in self.options:
            self._opts_meta["RHOSTS"] = Option(
                "RHOSTS", default=None,
                description="target(s): host | h1,h2 | CIDR | range | file:path",
            )
            self.options["RHOSTS"] = None
        self.framework = None

    def set_option(self, name, value):
        if name not in self.options:
            raise KeyError(f"unknown option: {name}")
        opt = self._opts_meta[name]
        self.options[name] = opt.type(value) if opt.type is not None else value

    def get_option(self, name):
        return self.options[name]

    def required_missing(self):
        missing = []
        rhosts_set = bool(self.options.get("RHOSTS"))
        for name, meta in self._opts_meta.items():
            if not meta.required:
                continue
            val = self.options[name]
            if val is None or val == "":
                if name == "RHOST" and rhosts_set:
                    continue
                missing.append(name)
        return missing

    def show_options(self):
        rows = sorted(
            self._opts_meta.items(),
            key=lambda kv: (not kv[1].required, kv[0]),
        )
        wname = max((len(n) for n in self.options), default=8)
        wreq = 3

        print(colors.heading(f"  {'Name'.ljust(wname)}  {'Req'.ljust(wreq)}  Value"))
        print(colors.dimmed(f"  {'-'*wname}  {'-'*wreq}  -----"))
        for name, meta in rows:
            val = self.options[name]
            shown = "" if val is None else str(val)
            req = colors.green("yes") if meta.required else colors.dimmed("no")
            req_pad = req + " " * (wreq - len("yes" if meta.required else "no"))
            print(f"  {name.ljust(wname)}  {req_pad}  {shown}")

    def resolve_targets(self) -> list[str]:
        if "RHOSTS" in self.options and self.options["RHOSTS"]:
            return parse_targets(self.options["RHOSTS"])
        if "RHOST" in self.options and self.options["RHOST"]:
            return parse_targets(self.options["RHOST"])
        return []

    def load_source(self):
        path = self.options.get("SOURCE")
        if not path:
            return False
        if not os.path.isfile(path):
            raise FileNotFoundError(f"SOURCE file not found: {path}")

        pairs = parse_source_file(path)
        applied, skipped = 0, 0
        for key, value in pairs.items():
            if key not in self.options:
                skipped += 1
                continue
            try:
                self.set_option(key, value)
                applied += 1
            except (TypeError, ValueError):
                skipped += 1

        print(colors.info(f"SOURCE: loaded {applied} option(s) from {path}"))
        if skipped:
            print(colors.dimmed(f"  ({skipped} unknown/invalid key(s) skipped)"))
        return True

    def check(self):
        from core.check import CheckResult
        return CheckResult.UNKNOWN

    def run(self):
        raise NotImplementedError

    def _db(self):
        if self.framework is None:
            return None
        return getattr(self.framework, "db", None)

    def report_host(self, address, **kwargs):
        db = self._db()
        if not db:
            return None
        try:
            return db.ensure_host(address, **kwargs)
        except Exception:
            return None

    def report_service(self, address, port, proto="tcp", **kwargs):
        db = self._db()
        if not db:
            return None
        try:
            return db.add_service(address, port, proto=proto, **kwargs)
        except Exception:
            return None

    def report_vuln(self, name, address=None, **kwargs):
        db = self._db()
        if not db:
            return None
        try:
            return db.add_vuln(
                name=name,
                host_address=address,
                module=self.NAME or type(self).__name__,
                **kwargs,
            )
        except Exception:
            return None

    def report_cred(self, address, username, secret, **kwargs):
        db = self._db()
        if not db:
            return None
        try:
            return db.add_cred(address, username, secret, **kwargs)
        except Exception:
            return None

    def note(self, data, address=None, kind="note"):
        db = self._db()
        if not db:
            return None
        try:
            return db.add_note(data, host_address=address, kind=kind)
        except Exception:
            return None
