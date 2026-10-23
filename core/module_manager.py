import importlib
import inspect
from pathlib import Path
from core.module import Module
from core.exploit import Exploit
from core.auxiliary import Auxiliary

DEFAULT_RANK = "normal"

class ModuleManager:
    def __init__(self, root="modules"):
        self.root = Path(root)
        self.modules: dict[str, type[Module]] = {}
        self._discover()

    def _discover(self):
        for pyfile in self.root.rglob("*.py"):
            if pyfile.name.startswith("_"):
                continue
            rel = pyfile.relative_to(self.root).with_suffix("")
            dotted = ".".join((self.root.name, *rel.parts))
            try:
                mod = importlib.import_module(dotted)
            except Exception as e:
                print(f"[-] failed to import {dotted}: {e}")
                continue
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                if obj is Module or obj in (Exploit, Auxiliary):
                    continue
                if issubclass(obj, Module) and obj.__module__ == dotted:
                    path = self._module_path(dotted)
                    self.modules[path] = obj

    def _module_path(self, dotted: str) -> str:
        parts = dotted.split(".")
        category = parts[1]
        if category.endswith("s"):
            category = category[:-1]
        name = "/".join(parts[2:])
        return f"{category}/{name}"

    def list(self):
        return sorted(self.modules.keys())

    def get(self, path: str) -> Module:
        cls = self.modules.get(path)
        if not cls:
            raise KeyError(f"no such module: {path}")
        return cls()

    def metadata(self, path: str) -> dict:
        cls = self.modules[path]

        check_fn = getattr(cls, "check", None)
        check_supported = bool(
            check_fn
            and check_fn is not Module.check
            and check_fn.__qualname__.split(".")[0] != "Module"
        )
        return {
            "path": path,
            "name": getattr(cls, "NAME", "") or path.rsplit("/", 1)[-1],
            "description": getattr(cls, "DESCRIPTION", "") or "",
            "rank": getattr(cls, "RANK", DEFAULT_RANK).lower(),
            "disclosed": getattr(cls, "DISCLOSED", "") or "",
            "check": check_supported,
            "author": getattr(cls, "AUTHOR", "") or "",
            "references": getattr(cls, "REFERENCES", []) or [],
        }

    def search(self, term: str):
        term = term.lower()
        return [m for m in self.list() if term in m.lower()]

    def search_detailed(self, term: str):
        term = term.lower()
        hits = []
        for path in self.list():
            meta = self.metadata(path)
            blob = " ".join([
                path,
                meta["name"],
                meta["description"],
                meta["author"],
                " ".join(meta["references"]),
            ]).lower()
            if term in blob:
                hits.append(meta)

        rank_order = {
            "excellent": 0, "great": 1, "good": 2,
            "normal": 3, "average": 3, "low": 4, "manual": 5,
        }
        hits.sort(key=lambda m: (
            rank_order.get(m["rank"], 99),
            -int(m["disclosed"].replace("-", "") or "0"),
            m["path"],
        ))
        return hits
