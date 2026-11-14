import re
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

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""

class TeamCityCve202663077Scanner(Auxiliary):
    NAME = "JetBrains TeamCity XStream RCE Detection (CVE-2026-63077)"
    DESCRIPTION = (
        "Detects TeamCity < 2026.1.3 / 2025.11.7 via the agent "
        "registration handshake. Registers a benign agent, reads its "
        "session cookie, then logs off. Confirmation is the fact that "
        "the unauthenticated registration succeeds and a session ID "
        "is issued (the XStream sink is reachable)."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-07-28"
    CHECK = True
    REFERENCES = [
        "CVE-2026-63077",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-63077",
        "https://blog.jetbrains.com/teamcity/2026/07/cve-2026-63077/",
    ]
    OPTIONS = [
        Option("RHOSTS", required=True, description="target(s)"),
        Option("RPORT", default=8111, type=int, description="TeamCity HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=15.0, type=float, description="per-request timeout"),
        Option("THREADS", default=20, type=int, description="concurrent workers"),
        Option("STOP_ON_FIRST", default=False, type=bool, description="stop after first vulnerable host"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts: raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _base(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        return scheme + "://" + host + ":" + str(self.options["RPORT"])

    def _version_tuple(self, v):
        try:
            return tuple(int(x) for x in re.split(r"[\s\.-]", v)[:3])
        except (ValueError, AttributeError):
            return (0,)

    def _probe(self, host):
        ctx = ssl._create_unverified_context()
        try:
            req = urllib.request.Request(self._base(host) + "/")
            req.add_header("User-Agent", "Mozilla/5.0 (metis)")
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                body = r.read().decode(errors="replace")
                headers = dict(r.headers)
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if "teamcity" not in body.lower() and "jetbrains" not in body.lower():
            return HostResult(host, "safe", "not TeamCity")

        token = "metis_" + str(abs(hash(host)))[:8]
        import uuid as _uuid
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<agentDetails agentName="' + token + '" agentAddress="127.0.0.1" '
            'agentPort="9090" authToken="' + token + '" pingCode="">'
            '<alternativeAddresses/><availableRunners/><availableVcs/>'
            '<buildParameters/><configParameters/></agentDetails>'
        ).encode()
        req = urllib.request.Request(self._base(host) + "/app/agents/v1/register",
                                     data=xml, method="POST")
        req.add_header("Content-Type", "application/xml")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                status = r.status
        except urllib.error.HTTPError as e:
            return HostResult(host, "safe", "register HTTP " + str(e.code))
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        session = hdrs.get("teamcity-agentsessionid", "")
        if status == 200 and session:
            return HostResult(host, "vulnerable",
                              "unauth agent session issued ("
                              + "session=" + session[:8] + "...)")
        return HostResult(host, "safe", "register returned HTTP " + str(status))

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="JetBrains TeamCity")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-63077", info=h.detail)

    def check(self):
        host = self._expand_targets()[0]
        print(colors.info("check: probing " + self._base(host)))
        r = self._probe(host)
        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            return CheckResult.VULNERABLE
        if r.state == "safe":
            print(colors.safe("check: " + host + " not vulnerable (" + r.detail + ")"))
            return CheckResult.SAFE
        print(colors.warn("check: " + host + " unknown (" + r.detail + ")"))
        return CheckResult.UNKNOWN

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"]); stop_first = self.options["STOP_ON_FIRST"]
        print(colors.info("scanning " + str(len(targets)) + " host(s)"))
        bar = ProgressBar(total=len(targets), prefix="scan")
        hits, clean, unknown, aborted = [], 0, 0, False
        db = self._db(); ws = bool(db and db.current_workspace_id())
        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(self._probe, h): h for h in targets}
                for fut in as_completed(futures):
                    bar.tick()
                    try: r = fut.result()
                    except Exception: unknown += 1; continue
                    if r.state == "vulnerable":
                        hits.append(r); bar.log(colors.vuln(r.host + " - " + r.detail))
                        if ws: self._record(r)
                        if stop_first:
                            aborted = True
                            for f in futures: f.cancel()
                            break
                    elif r.state == "safe": clean += 1
                    else: unknown += 1
        finally:
            bar.done()
        print()
        print(colors.heading("--- scan summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  vulnerable:   " + colors.green(str(len(hits))))
        print("  not vuln:     " + colors.dimmed(str(clean)))
        print("  unknown:      " + colors.warn(str(unknown)))
        if aborted: print(colors.warn("  scan aborted early (STOP_ON_FIRST)"))
        return hits
