import json
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

JOLOKIA = "/api/jolokia/"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    broker: str = ""

class ActiveMQCve202634197Scanner(Auxiliary):
    NAME = "Apache ActiveMQ Jolokia RCE Detection (CVE-2026-34197)"
    DESCRIPTION = (
        "Detects unauthenticated Jolokia access on the ActiveMQ web "
        "console. If /api/jolokia/version responds without auth and a "
        "Broker MBean is discoverable, the addNetworkConnector operation "
        "is reachable and RCE via xbean Spring XML is possible."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    SEVERITY = "critical"
    DISCLOSED = "2026-05-11"
    CHECK = True
    REFERENCES = [
        "CVE-2026-34197",
        "https://nvd.nist.gov/vuln/detail/CVE-2026-34197",
        "https://horizon3.ai/attack-research/disclosures/cve-2026-34197-activemq-rce-jolokia/",
    ]
    OPTIONS = [
        Option("RHOSTS", required=True, description="target(s)"),
        Option("RPORT", default=8161, type=int, description="ActiveMQ web console port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=10.0, type=float, description="per-request timeout"),
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

    def _get(self, host, path):
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(self._base(host) + path)
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except urllib.error.URLError:
            raise

    def _probe(self, host):
        try:
            st, body = self._get(host, JOLOKIA + "version")
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", type(e).__name__)
        if st == 401:
            return HostResult(host, "safe", "Jolokia requires auth")
        if st != 200:
            return HostResult(host, "safe", "HTTP " + str(st))

        payload = json.dumps({"type": "search", "mbean": "org.apache.activemq:*"}).encode()
        ctx = ssl._create_unverified_context()
        req = urllib.request.Request(self._base(host) + JOLOKIA, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 (metis)")
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"], context=ctx) as r:
                data = json.loads(r.read().decode(errors="replace") or "{}")
        except (urllib.error.HTTPError, ValueError):
            return HostResult(host, "unknown", "search failed")
        for mbean in (data.get("value") or []):
            if "brokerName=" in mbean and "type=Broker" in mbean:
                broker = mbean.split("brokerName=")[1].split(",")[0]
                return HostResult(host, "vulnerable",
                                  "Jolokia open, Broker MBean found", broker)
        return HostResult(host, "safe", "Jolokia open but no Broker MBean")

    def _record(self, h):
        svc = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(h.host, self.options["RPORT"], proto="tcp",
                            state="open", name=svc, banner="Apache ActiveMQ")
        self.report_vuln(name=self.NAME, address=h.host, severity="critical",
                         refs="CVE-2026-34197",
                         info=h.detail + " | broker=" + h.broker)

    def check(self):
        host = self._expand_targets()[0]
        print(colors.info("check: probing " + self._base(host) + JOLOKIA))
        r = self._probe(host)
        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail
                              + ", broker=" + r.broker + ")"))
            return CheckResult.VULNERABLE
        if r.state == "safe":
            print(colors.safe("check: " + host + " not vulnerable (" + r.detail + ")"))
            return CheckResult.SAFE
        print(colors.warn("check: " + host + " unknown (" + r.detail + ")"))
        return CheckResult.UNKNOWN

    def action(self):
        targets = self._expand_targets()
        threads = max(1, self.options["THREADS"]); stop_first = self.options["STOP_ON_FIRST"]
        print(colors.info("scanning " + str(len(targets)) + " host(s) with " + str(threads) + " threads"))
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
