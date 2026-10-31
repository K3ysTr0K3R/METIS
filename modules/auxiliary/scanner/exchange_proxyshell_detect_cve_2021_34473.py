import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

PROBE_PATHS = [
    "/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com",
    "/autodiscover/autodiscover.json?@test.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@test.com",
]

MATCH_STRINGS = [
    "Microsoft.Exchange.Clients.Owa2.Server.Core.OwaADUserNotFoundException",
    "Exchange MAPI/HTTP Connectivity Endpoint",
]


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    matched_path: str = ""


class ExchangeProxyshellDetect(Auxiliary):
    NAME = "Microsoft Exchange ProxyShell SSRF Detection Scanner (CVE-2021-34473)"
    DESCRIPTION = (
        "Detects Microsoft Exchange servers vulnerable to the ProxyShell "
        "SSRF (CVE-2021-34473). The vulnerability is a path-confusion flaw "
        "in the Autodiscover endpoint that allows an unauthenticated "
        "attacker to access the Exchange backend. This scanner requests "
        "the two known SSRF paths and matches the response bodies against "
        "OwaADUserNotFoundException or Exchange MAPI/HTTP signatures. "
        "Detection only - no exploitation, no webshell upload, no auth "
        "bypass. Affects Exchange 2013 CU23, 2016 CU19/CU20, 2019 CU8/CU9."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2021-07-13"
    CHECK = True
    REFERENCES = [
        "CVE-2021-34473",
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473",
        "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-34473",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=443, type=int, description="HTTPS port"),
        Option("SSL", default=True, type=bool, description="use HTTPS (required for Exchange)"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first vulnerable host"),
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

    def _get(self, host, path):
        url = self._base_url(host) + path
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        req.add_header("Accept", "*/*")
        try:
            with urllib.request.urlopen(
                req, timeout=self.options["TIMEOUT"], context=ctx
            ) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except urllib.error.URLError:
            raise

    def _probe(self, host):
        result = HostResult(host=host)

        for path in PROBE_PATHS:
            try:
                st, body = self._get(host, path)
            except urllib.error.URLError as e:
                result.detail = type(e).__name__
                return result

            if st != 200:
                continue

            for sig in MATCH_STRINGS:
                if sig in body:
                    result.state = "vulnerable"
                    result.matched_path = path
                    result.detail = "SSRF confirmed via " + sig.split(".")[-1][:30]
                    return result

        result.state = "safe"
        result.detail = "no SSRF signature in response"
        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="Microsoft Exchange",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2021-34473",
            info=h.detail + " | path=" + h.matched_path,
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
        print(colors.dimmed("  paths: /autodiscover/autodiscover.json?@test.com/..."))

        r = self._probe(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            print(colors.dimmed("  path: " + r.matched_path))
            return CheckResult.VULNERABLE
        if r.state == "safe":
            print(colors.safe("check: " + host + " not vulnerable (" + r.detail + ")"))
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

                    if r.state == "vulnerable":
                        hits.append(r)
                        bar.log(colors.vuln(r.host + " - " + r.detail))
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

        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  vulnerable:   " + colors.green(str(len(hits))))
        print("  not vuln:     " + colors.dimmed(str(clean)))
        print("  unknown:      " + colors.warn(str(unknown)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} vuln(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  vulnerable hosts:"))
            for h in hits:
                print("    " + colors.vuln(h.host) + "  " + colors.dimmed(h.detail))

        return hits
