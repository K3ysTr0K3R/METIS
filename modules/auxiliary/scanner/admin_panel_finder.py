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

DEFAULT_PATHS = ",".join([
    "/admin/", "/admin", "/administrator/", "/admin.php", "/admin/login",
    "/admin/login.php", "/admin/index.php", "/adminpanel/", "/panel/",
    "/control/", "/controlpanel/", "/cpanel/", "/dashboard/", "/login/",
    "/login.php", "/login.html", "/signin/", "/manager/", "/manager/html",
    "/wp-admin/", "/wp-login.php", "/user/login", "/users/sign_in",
    "/backend/", "/backoffice/", "/console/", "/webadmin/", "/portal/",
    "/moderator/", "/root/", "/siteadmin/", "/account/login",
    "/admincp/", "/admin_area/", "/adm/", "/management/", "/sysadmin/",
])

DEFAULT_KEYWORDS = "login,username,password,sign in,log in,admin,auth"

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class PanelHit:
    path: str
    url: str
    status_code: int
    title: str | None = None


@dataclass
class HostResult:
    host: str
    port: int
    hits: list[PanelHit] = field(default_factory=list)
    error: str | None = None


class AdminPanelFinder(Auxiliary):
    NAME = "Admin Panel Finder"
    DESCRIPTION = (
        "Probes a list of common admin/login panel paths and flags hits by "
        "status code, optionally confirmed with body keyword matching. "
        "Supports single hosts, comma lists, CIDR, ranges, and file: "
        "target specs."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    CHECK = True

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="target port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("PATHS", default=DEFAULT_PATHS,
               description="comma-separated panel paths to check"),
        Option("STATUS_CODES", default="200,301,302,401,403",
               description="comma-separated status codes counted as a hit"),
        Option("MATCH_BODY", default=True, type=bool,
               description="for 200 responses, also require a body keyword match"),
        Option("BODY_KEYWORDS", default=DEFAULT_KEYWORDS,
               description="comma-separated keywords checked against the body on 200s"),
        Option("FOLLOW_REDIRECTS", default=False, type=bool,
               description="follow redirects instead of treating 301/302 as hits"),
        Option("TIMEOUT", default=8.0, type=float, description="per-request timeout"),
        Option("THREADS", default=10, type=int, description="concurrent workers (host scan)"),
        Option("PATH_THREADS", default=10, type=int,
               description="concurrent workers per host (path scan)"),
        Option("FIND_ALL", default=True, type=bool,
               description="keep scanning after first hit (off = stop at first per host)"),
        Option("USER_AGENT", default="Mozilla/5.0 (METIS admin-panel-finder)",
               description="User-Agent header sent with each request"),
    ]

    def _expand_targets(self) -> list[str]:
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info(f"target list -> {len(hosts)} hosts"))
        return hosts

    def _get_paths(self) -> list[str]:
        paths = self.options["PATHS"] or "/admin/"
        return [p.strip() for p in paths.split(",") if p.strip()]

    def _get_status_codes(self) -> set[int]:
        raw = self.options["STATUS_CODES"] or "200"
        return {int(c.strip()) for c in raw.split(",") if c.strip()}

    def _get_keywords(self) -> list[str]:
        raw = self.options["BODY_KEYWORDS"] or ""
        return [k.strip().lower() for k in raw.split(",") if k.strip()]

    def _base_url(self, host: str) -> str:
        scheme = "https" if self.options["SSL"] else "http"
        return f"{scheme}://{host}:{self.options['RPORT']}"

    def _extract_title(self, body: str) -> str | None:
        m = TITLE_RE.search(body)
        if not m:
            return None
        return re.sub(r"\s+", " ", m.group(1)).strip()[:80] or None

    def _check_path(self, base: str, path: str, codes: set[int],
                     keywords: list[str]) -> PanelHit | None:
        url = base.rstrip("/") + "/" + path.lstrip("/")
        try:
            response = requests.get(
                url,
                timeout=self.options["TIMEOUT"],
                verify=False,
                allow_redirects=self.options["FOLLOW_REDIRECTS"],
                headers={"User-Agent": self.options["USER_AGENT"]},
            )
        except requests.RequestException:
            return None

        if response.status_code not in codes:
            return None

        title = None
        if response.status_code == 200:
            body = response.text[:200_000]
            title = self._extract_title(body)
            if self.options["MATCH_BODY"] and keywords:
                low = body.lower()
                if not any(kw in low for kw in keywords):
                    return None

        return PanelHit(path=path, url=response.url, status_code=response.status_code, title=title)

    def _probe(self, host: str) -> HostResult:
        port = self.options["RPORT"]
        base = self._base_url(host)
        codes = self._get_status_codes()
        keywords = self._get_keywords()
        paths = self._get_paths()
        find_all = self.options["FIND_ALL"]
        path_workers = max(1, self.options["PATH_THREADS"])

        res = HostResult(host=host, port=port)

        try:
            with ThreadPoolExecutor(max_workers=path_workers) as ex:
                futures = {
                    ex.submit(self._check_path, base, p, codes, keywords): p
                    for p in paths
                }
                for fut in as_completed(futures):
                    hit = fut.result()
                    if hit:
                        res.hits.append(hit)
                        if not find_all:
                            for f in futures:
                                f.cancel()
                            break
        except Exception as e:
            res.error = type(e).__name__

        res.hits.sort(key=lambda h: h.path)
        return res

    def _record_host_result(self, res):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(res.host, state="up")
        self.report_service(
            res.host, res.port,
            proto="tcp", state="open",
            name=svc_name, banner="",
        )
        for hit in res.hits:
            note = "panel=" + hit.url + " [" + str(hit.status_code) + "]"
            if hit.title:
                note += ' "' + hit.title + '"'
            self.note(note, address=res.host, kind="admin_panel")

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
        if res.hits:
            for hit in res.hits:
                print(colors.vuln(
                    f"check: {host} -> {hit.url} [{hit.status_code}]"
                    + (f' "{hit.title}"' if hit.title else "")
                ))
            return CheckResult.VULNERABLE
        print(colors.safe(f"check: {host} no admin panel found"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])

        print(colors.info(f"scanning {len(targets)} host(s) with {threads} threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits, errors = [], 0

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
                    if res.hits:
                        hits.append(res)
                        for hit in res.hits:
                            bar.log(colors.vuln(
                                f"{res.host}:{res.port} -> {hit.url} [{hit.status_code}]"
                                + (f' "{hit.title}"' if hit.title else "")
                            ))
                        if workspace_active:
                            self._record_host_result(res)
                    elif res.error:
                        errors += 1
        finally:
            bar.done()

        total_hits = sum(len(h.hits) for h in hits)
        print()
        print(colors.heading("--- scan summary ---"))
        print(f"  targets:        {len(targets)}")
        print(f"  hosts w/ panel: {colors.green(str(len(hits)))}")
        print(f"  panels found:   {colors.green(str(total_hits))}")
        print(f"  errors/skips:   {colors.dimmed(str(errors))}")
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:       " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{total_hits} note(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  found panels:"))
            for h in hits:
                for hit in h.hits:
                    label = f"    {colors.vuln(h.host)}:{h.port} -> {hit.url} [{hit.status_code}]"
                    if hit.title:
                        label += f' "{hit.title}"'
                    print(label)
        return hits
