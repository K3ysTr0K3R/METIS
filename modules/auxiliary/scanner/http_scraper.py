import html
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
WS_RE = re.compile(r"\s+")
DEFAULT_PATHS = "/"

@dataclass
class PageHit:
    path: str
    url: str
    status: int
    title: str = ""
    server: str = ""
    content_type: str = ""
    size: int = 0
    error: str = ""


@dataclass
class HostResult:
    host: str
    port: int
    hits: list = field(default_factory=list)
    error: str = ""


class HTTPScraper(Auxiliary):
    NAME = "HTTP Scraper"
    DESCRIPTION = (
        "Fetches HTTP(S) pages and extracts the <title> tag content from "
        "each. Reports status code, title, server header, content type, and "
        "response size. Supports single hosts, comma lists, CIDR, ranges, "
        "and file: target specs."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "info"
    CHECK = True

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("PATHS", default=DEFAULT_PATHS,
               description="comma-separated paths to fetch"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers (host scan)"),
        Option("PATH_THREADS", default=5, type=int,
               description="concurrent workers per host (path scan)"),
        Option("FOLLOW_REDIRECTS", default=True, type=bool,
               description="follow HTTP redirects"),
        Option("SHOW_EMPTY", default=False, type=bool,
               description="also report pages without a <title>"),
        Option("MAX_BODY", default=512 * 1024, type=int,
               description="maximum response bytes to scan for a title"),
        Option("USER_AGENT", default="Mozilla/5.0 (METIS http-scraper)",
               description="User-Agent header sent with each request"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _get_paths(self):
        raw = self.options["PATHS"] or "/"
        return [p.strip() for p in raw.split(",") if p.strip()]

    def _base_url(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _extract_title(self, body):
        m = TITLE_RE.search(body)
        if not m:
            return ""
        raw = m.group(1)
        text = html.unescape(raw)
        text = WS_RE.sub(" ", text).strip()
        return text[:200]

    def _fetch(self, url):
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", self.options["USER_AGENT"])
        req.add_header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        try:
            with urllib.request.urlopen(
                req,
                timeout=self.options["TIMEOUT"],
                context=ctx,
            ) as r:
                content_type = r.headers.get("Content-Type", "")
                server = r.headers.get("Server", "")
                body_bytes = r.read(self.options["MAX_BODY"])
                charset = "utf-8"
                m = re.search(r"charset=([\w-]+)", content_type, re.I)
                if m:
                    charset = m.group(1)
                try:
                    body = body_bytes.decode(charset, errors="replace")
                except LookupError:
                    body = body_bytes.decode("utf-8", errors="replace")
                return (
                    r.status, body, server, content_type, len(body_bytes),
                    r.geturl(),
                )
        except urllib.error.HTTPError as e:
            try:
                body_bytes = e.read(self.options["MAX_BODY"])
                body = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return (
                e.code, body,
                e.headers.get("Server", "") if e.headers else "",
                e.headers.get("Content-Type", "") if e.headers else "",
                len(body.encode("utf-8", errors="replace")),
                url,
            )
        except urllib.error.URLError as e:
            raise
        except (socket.timeout, TimeoutError):
            raise
        except OSError:
            raise

    def _scrape_path(self, base, path):
        url = base.rstrip("/") + "/" + path.lstrip("/")
        try:
            status, body, server, ctype, size, final_url = self._fetch(url)
        except urllib.error.URLError as e:
            return PageHit(path=path, url=url, status=0, error=type(e).__name__)
        except (socket.timeout, TimeoutError):
            return PageHit(path=path, url=url, status=0, error="timeout")
        except OSError as e:
            return PageHit(path=path, url=url, status=0, error=type(e).__name__)

        title = ""
        if "html" in (ctype or "").lower() or "<title" in body.lower():
            title = self._extract_title(body)

        return PageHit(
            path=path, url=final_url or url, status=status,
            title=title, server=server or "",
            content_type=ctype or "", size=size,
        )

    def _probe(self, host):
        base = self._base_url(host)
        paths = self._get_paths()
        path_workers = max(1, self.options["PATH_THREADS"])
        result = HostResult(host=host, port=self.options["RPORT"])

        try:
            with ThreadPoolExecutor(max_workers=path_workers) as ex:
                futures = {ex.submit(self._scrape_path, base, p): p for p in paths}
                for fut in as_completed(futures):
                    try:
                        hit = fut.result()
                    except Exception as e:
                        result.error = type(e).__name__
                        continue
                    if hit.error:
                        if hit.error not in ("URLError",):
                            result.error = hit.error
                        continue
                    if hit.title or self.options["SHOW_EMPTY"]:
                        result.hits.append(hit)
        except Exception as e:
            result.error = type(e).__name__

        result.hits.sort(key=lambda h: h.path)
        return result

    def _record_host_result(self, res, svc_name):
        self.report_host(res.host, state="up")

        banner = ""
        for hit in res.hits:
            if hit.server:
                banner = hit.server
                break

        self.report_service(
            res.host, res.port,
            proto="tcp", state="open",
            name=svc_name, banner=banner,
        )

        for hit in res.hits:
            bits = [
                hit.url,
                "[" + str(hit.status) + "]",
                hit.title or "(no title)",
            ]
            if hit.server:
                bits.append("server=" + hit.server)
            if hit.content_type:
                bits.append("ctype=" + hit.content_type)
            self.note(
                " ".join(bits),
                address=res.host,
                kind="http_title",
            )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))
        r = self._probe(host)

        if r.hits:
            for hit in r.hits:
                print(colors.good(
                    "check: " + hit.url + " [" + str(hit.status) + "] "
                    + (hit.title or "(no title)")
                ))
            return CheckResult.UNKNOWN
        if r.error:
            print(colors.safe("check: " + host + " error (" + r.error + ")"))
        else:
            print(colors.safe("check: " + host + " no titles found"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])

        print(colors.info("scraping " + str(len(targets)) + " host(s) with "
                          + str(threads) + " threads"))
        bar = ProgressBar(total=len(targets), prefix="scrape")
        hits = []
        errors = 0

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())
        svc_name = "https" if self.options["SSL"] else "http"

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

                    if not res.hits:
                        if res.error:
                            errors += 1
                        continue

                    hits.append(res)
                    for hit in res.hits:
                        bar.log(colors.good(
                            res.host + " -> " + (hit.title or "(no title)")
                        ))

                    if workspace_active:
                        self._record_host_result(res, svc_name)
        finally:
            bar.done()

        total_pages = sum(len(h.hits) for h in hits)
        print()
        print(colors.heading("--- scrape summary ---"))
        print("  targets:        " + str(len(targets)))
        print("  hosts w/title:  " + colors.green(str(len(hits))))
        print("  pages titled:   " + colors.green(str(total_pages)))
        print("  errors/skips:   " + colors.dimmed(str(errors)))
        if workspace_active and hits:
            ws = db.current_workspace()
            total_notes = sum(len(h.hits) for h in hits)
            print("  recorded:       " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{total_notes} note(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  titles:"))
            for h in hits:
                for hit in h.hits:
                    line = "    " + colors.vuln(hit.url)
                    line += " [" + str(hit.status) + "]"
                    if hit.server:
                        line += " " + colors.dimmed("(" + hit.server + ")")
                    print(line)
                    print("      " + colors.session(hit.title or "(no title)"))
                    if hit.content_type:
                        print("      " + colors.dimmed(
                            hit.content_type + " | " + str(hit.size) + " bytes"
                        ))

        return hits
