import json
import re
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

REST_USERS_PATH = "/wp-json/wp/v2/users"
AUTHOR_PATH = "/?author={}"
OEMBED_PATH = "/wp-json/oembed/1.0/embed?url={}&format=json"

MAX_AUTHOR_ID = 10


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    usernames: list = field(default_factory=list)


class WordPressUserEnum(Auxiliary):
    NAME = "WordPress Username Enumeration Scanner"
    DESCRIPTION = (
        "Enumerates valid WordPress usernames via three unauthenticated "
        "vectors: the REST API (/wp-json/wp/v2/users), author archive "
        "redirects (/?author=N), and the oEmbed endpoint. The REST API "
        "exposes the slug (login name) of users who have published posts. "
        "Author archives redirect to /author/<slug>/ which reveals the "
        "login name. Detection only - no authentication attempts, no "
        "brute force. Records discovered usernames as kind=username creds."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "info"
    CHECK = True
    REFERENCES = [
        "https://developer.wordpress.org/rest-api/reference/users/",
        "https://cirt.gov.jm/article/wordpress-user-enumeration-vulnerability-risks-mitigation-steps",
        "https://wordpress.org/support/topic/found-a-user-enumeration-that-is-not-stopped/",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers"),
        Option("MAX_AUTHOR_ID", default=MAX_AUTHOR_ID, type=int,
               description="highest author ID to probe (/?author=N)"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first host with users found"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _base_url(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _get(self, host, path, allow_redirects=False):
        url = self._base_url(host) + path
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Accept", "application/json,text/html,*/*")

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        if allow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx)
            )
        else:
            opener = urllib.request.build_opener(
                NoRedirect(),
                urllib.request.HTTPSHandler(context=ctx),
            )

        try:
            with opener.open(req, timeout=self.options["TIMEOUT"]) as r:
                return r.status, dict(r.headers), r.read(200_000)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {}), e.read(200_000)
        except urllib.error.URLError:
            raise

    def _enum_rest_api(self, host):
        """Extract slugs from /wp-json/wp/v2/users."""
        usernames = []
        try:
            st, _headers, body = self._get(host, REST_USERS_PATH)
        except urllib.error.URLError:
            return usernames

        if st != 200:
            return usernames

        try:
            data = json.loads(body.decode(errors="replace"))
        except (ValueError, AttributeError):
            return usernames

        if not isinstance(data, list):
            return usernames

        for user in data:
            if not isinstance(user, dict):
                continue
            slug = user.get("slug")
            if slug and isinstance(slug, str):
                usernames.append(slug)
        return usernames

    def _enum_author_redirect(self, host):
        """Follow /?author=N and extract slug from Location header."""
        usernames = []
        max_id = max(1, int(self.options["MAX_AUTHOR_ID"]))
        for n in range(1, max_id + 1):
            try:
                st, headers, _body = self._get(host, AUTHOR_PATH.format(n))
            except urllib.error.URLError:
                continue

            location = headers.get("Location") or headers.get("location", "")
            if not location:
                continue

            m = re.search(r"/author/([^/?#]+)/?", location)
            if m:
                slug = urllib.parse.unquote(m.group(1))
                if slug and slug not in usernames:
                    usernames.append(slug)
        return usernames

    def _enum_oembed(self, host):
        """Probe oEmbed for author_name on the site root post."""
        usernames = []
        root_url = self._base_url(host) + "/"
        path = OEMBED_PATH.format(urllib.parse.quote(root_url, safe=""))
        try:
            st, _headers, body = self._get(host, path)
        except urllib.error.URLError:
            return usernames

        if st != 200:
            return usernames

        try:
            data = json.loads(body.decode(errors="replace"))
        except (ValueError, AttributeError):
            return usernames

        if isinstance(data, dict):
            author = data.get("author_name")
            if author and isinstance(author, str):
                usernames.append(author)
        return usernames

    def _probe(self, host):
        result = HostResult(host=host)

        try:
            st, _headers, body = self._get(host, "/")
        except urllib.error.URLError as e:
            result.detail = type(e).__name__
            return result

        page = body.decode(errors="replace")
        if "wp-content" not in page and "wp-includes" not in page:
            result.state = "safe"
            result.detail = "not WordPress"
            return result

        all_users = []

        rest_users = self._enum_rest_api(host)
        if rest_users:
            all_users.extend(rest_users)

        author_users = self._enum_author_redirect(host)
        for u in author_users:
            if u not in all_users:
                all_users.append(u)

        oembed_users = self._enum_oembed(host)
        for u in oembed_users:
            if u not in all_users:
                all_users.append(u)

        if all_users:
            result.state = "confirmed"
            result.usernames = all_users
            sources = []
            if rest_users:
                sources.append("REST API")
            if author_users:
                sources.append("author redirect")
            if oembed_users:
                sources.append("oEmbed")
            result.detail = (
                str(len(all_users)) + " user(s) via " + ", ".join(sources)
            )
            return result

        result.state = "safe"
        result.detail = "no usernames exposed"
        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="WordPress",
        )
        for username in h.usernames:
            self.report_cred(
                h.host, username, "",
                kind="username",
                info="WordPress user enumeration",
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

        if r.state == "confirmed":
            print(colors.good("check: " + host + " - " + r.detail))
            for u in r.usernames[:10]:
                print(colors.dimmed("  user: " + u))
            return CheckResult.UNKNOWN
        if r.state == "safe":
            print(colors.safe("check: " + host + " - " + r.detail))
            return CheckResult.SAFE
        print(colors.warn("check: " + host + " unknown (" + r.detail + ")"))
        return CheckResult.UNKNOWN

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]

        print(colors.info(
            "scanning " + str(len(targets)) + " host(s) with "
            + str(threads) + " threads"
        ))

        bar = ProgressBar(total=len(targets), prefix="scan")
        hits = []
        clean = 0
        unknown = 0
        aborted = False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._probe, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        r = fut.result()
                    except Exception:
                        unknown += 1
                        continue

                    if r.state == "confirmed":
                        hits.append(r)
                        bar.log(colors.good(
                            r.host + " - " + r.detail
                        ))
                        if workspace_active:
                            self._record_host_result(r)
                        if stop_first:
                            aborted = True
                            for f in futures:
                                f.cancel()
                            break
                    elif r.state == "safe":
                        clean += 1
                    else:
                        unknown += 1
        finally:
            bar.done()

        total_users = sum(len(h.usernames) for h in hits)
        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  hosts w/users:" + colors.green(str(len(hits))))
        print("  users found:  " + colors.green(str(total_users)))
        print("  no users:     " + colors.dimmed(str(clean)))
        print("  unknown:      " + colors.warn(str(unknown)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{total_users} username cred(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  enumerated usernames:"))
            for h in hits:
                print("    " + colors.good(h.host) + "  " + colors.dimmed(h.detail))
                for u in h.usernames:
                    print("      " + colors.session(u))

        return hits
