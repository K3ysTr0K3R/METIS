import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import requests
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

DIRECTORY_SIGNATURES = (
    r"<title>\s*Index of\s+/",
    r"<h1>\s*Index of\s+/",
    r"Directory listing for",
    r"Parent Directory",
    r"Directory Listing",
    r"Index of /",
)

@dataclass
class HostResult:
    host: str
    port: int
    vulnerable: bool = False
    matched_path: str | None = None
    url: str | None = None
    error: str | None = None
    checked: list[str] = field(default_factory=list)


class DirectoryListingScanner(Auxiliary):
    NAME = "Directory Listing Scanner"
    DESCRIPTION = (
        "Detects publicly accessible directory listings across one or more "
        "paths. Supports single hosts, comma lists, CIDR, ranges, and "
        "file: target specs."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="target port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("PATHS", default="/,/uploads/,/files/,/backup/,/assets/,/static/",
               description="comma-separated paths to check"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers (host scan)"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first vulnerable host"),
    ]

    def _expand_targets(self) -> list[str]:
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info(f"target list -> {len(hosts)} hosts"))
        return hosts

    def _get_paths(self) -> list[str]:
        paths = self.options["PATHS"] or "/"
        return [p.strip() for p in paths.split(",") if p.strip()]

    def _base_url(self, host: str) -> str:
        scheme = "https" if self.options["SSL"] else "http"
        return f"{scheme}://{host}:{self.options['RPORT']}"

    def _is_directory_listing(self, response) -> bool:
        if response.status_code != 200:
            return False
        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            return False
        body = response.text[:200_000]
        return any(
            re.search(sig, body, re.IGNORECASE)
            for sig in DIRECTORY_SIGNATURES
        )

    def _probe(self, host: str) -> HostResult:
        port = self.options["RPORT"]
        timeout = self.options["TIMEOUT"]
        base = self._base_url(host)
        res = HostResult(host=host, port=port)

        for path in self._get_paths():
            url = base.rstrip("/") + "/" + path.lstrip("/")
            res.checked.append(path)
            try:
                response = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
            except requests.RequestException as e:
                res.error = type(e).__name__
                continue

            if self._is_directory_listing(response):
                res.vulnerable = True
                res.matched_path = path
                res.url = response.url
                res.error = None
                return res

        return res

    def _record_host_result(self, res):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(res.host, state="up")
        self.report_service(
            res.host, res.port,
            proto="tcp", state="open",
            name=svc_name, banner="",
        )
        self.note(
            "dir_listing=" + (res.url or "") + " path=" + (res.matched_path or ""),
            address=res.host,
            kind="dir_listing",
        )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                f"check on multiple targets: probing only {targets[0]} "
                f"(use 'run' to scan all {len(targets)})"
            ))
        host = targets[0]
        print(colors.info(f"check: probing {host}:{self.options['RPORT']}"))
        res = self._probe(host)
        if res.vulnerable:
            print(colors.vuln(f"check: {host} directory listing at {res.url}"))
            return CheckResult.VULNERABLE
        print(colors.safe(f"check: {host} no directory listing found"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info(f"scanning {len(targets)} host(s) with {threads} threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits, errors, aborted = [], 0, False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._probe, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        res = fut.result()
                    except Exception:
                        errors += 1
                        continue
                    if res.vulnerable:
                        hits.append(res)
                        bar.log(colors.vuln(f"{res.host}:{res.port} -> {res.url}"))
                        if workspace_active:
                            self._record_host_result(res)
                        if stop_first:
                            aborted = True
                            for f in futures:
                                f.cancel()
                            break
                    elif res.error:
                        errors += 1
        finally:
            bar.done()

        print()
        print(colors.heading("--- scan summary ---"))
        print(f"  targets:      {len(targets)}")
        print(f"  vulnerable:   {colors.green(str(len(hits)))}")
        print(f"  errors/skips: {colors.dimmed(str(errors))}")
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} note(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  vulnerable hosts:"))
            for h in hits:
                print(f"    {colors.vuln(h.host)}:{h.port} -> {h.url}")
        return hits
