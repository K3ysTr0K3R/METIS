import asyncio
import re
from dataclasses import dataclass, field
from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar

ROUTEROS_INDICATORS = [
    "mikrotik routeros > administration",
    "Mikrotik Router",
    "/webcfg/",
    "RouterOS",
    "mikrotik routeros",
]

VERSION_RE = re.compile(
    r"(?:RouterOS|mikrotik routeros)\s*(?:v|version)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)

@dataclass
class HostResult:
    host: str
    port: int
    state: str = "down"
    detected: bool = False
    version: str = ""
    matched: list = field(default_factory=list)
    error: str | None = None


class MikroTikRouterOSHTTPDetect(Auxiliary):
    NAME = "MikroTik RouterOS HTTP Detection Scanner"
    DESCRIPTION = (
        "Detects MikroTik RouterOS WebFig interfaces via HTTP. Sends a GET "
        "to the root path and matches indicators from the Nuclei template "
        "(e.g., 'mikrotik routeros > administration', '/webcfg/'). "
        "Detection only — finding RouterOS is informational, not a "
        "vulnerability verdict. Uses asyncio for high-speed sweeps; THREADS "
        "is a concurrency limit and can be raised above 50 for fast "
        "large-range scans."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "normal"
    SEVERITY = "info"
    DISCLOSED = "2026-10-17"
    CHECK = True
    REFERENCES = [
        "https://github.com/runZeroInc/nuclei-templates/blob/main/http/exposed-panels/mikrotik/mikrotik-routeros.yaml",
    ]

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("RPORT", default=80, type=int, description="HTTP port"),
        Option("SSL", default=False, type=bool, description="use HTTPS"),
        Option("TIMEOUT", default=5.0, type=float, description="per-request timeout"),
        Option("THREADS", default=50, type=int,
               description="concurrent HTTP requests (raise to 2000+ for fast large-range sweeps)"),
        Option("FOLLOW_REDIRECTS", default=True, type=bool,
               description="follow HTTP redirects (RouterOS often redirects to /webfig/)"),
        Option("USER_AGENT", default="Mozilla/5.0 (metis)",
               description="User-Agent header"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets — set RHOSTS (or use run <target>)")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _base_url(self, host):
        scheme = "https" if self.options["SSL"] else "http"
        port = self.options["RPORT"]
        default = 443 if scheme == "https" else 80
        if port == default:
            return "{}://{}".format(scheme, host)
        return "{}://{}:{}".format(scheme, host, port)

    async def _probe_async(self, host, sem):
        result = HostResult(host=host, port=self.options["RPORT"])
        url = self._base_url(host)
        timeout = self.options["TIMEOUT"]
        follow = self.options["FOLLOW_REDIRECTS"]
        ua = self.options["USER_AGENT"]

        async with sem:
            try:
                import aiohttp
                connector = aiohttp.TCPConnector(ssl=False, limit=0)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=follow,
                        headers={"User-Agent": ua},
                    ) as resp:
                        body = await resp.text(errors="replace")
            except ImportError:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, self.options["RPORT"]),
                        timeout=timeout,
                    )
                    request = (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: {ua}\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    writer.write(request.encode())
                    await writer.drain()
                    body_bytes = await asyncio.wait_for(
                        reader.read(8192), timeout=timeout
                    )
                    body = body_bytes.decode("utf-8", errors="replace")
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    result.error = type(e).__name__
                    return result
            except Exception as e:
                result.error = type(e).__name__
                return result

        result.state = "up"

        matched = []
        lower_body = body.lower()
        for ind in ROUTEROS_INDICATORS:
            if ind.lower() in lower_body:
                matched.append(ind)

        if matched:
            result.detected = True
            result.matched = matched
            m = VERSION_RE.search(body)
            if m:
                result.version = m.group(1)
        else:
            result.error = "no RouterOS indicators"

        return result

    def _record_host_result(self, h):
        self.report_host(h.host, state="up")
        banner = "RouterOS"
        if h.version:
            banner += " " + h.version
        self.report_service(
            h.host, h.port,
            proto="tcp", state="open",
            name="http", banner=banner,
        )
        bits = ["detected=RouterOS"]
        if h.version:
            bits.append("version=" + h.version)
        bits.append("indicators=" + "|".join(h.matched))
        self.note(" ".join(bits), address=h.host, kind="mikrotik_info")

    def _phase_async(self, targets, bar):
        async def _run():
            sem = asyncio.Semaphore(self.options["THREADS"])
            tasks = [asyncio.create_task(self._probe_async(h, sem)) for h in targets]
            hits = []
            for coro in asyncio.as_completed(tasks):
                r = await coro
                bar.tick()
                if r.detected:
                    hits.append(r)
                    ver = " v" + r.version if r.version else ""
                    bar.log(colors.good(r.host + "  [RouterOS]" + ver))
            return hits

        return asyncio.run(_run())

    def check(self):
        targets = self._expand_targets()
        if len(targets) > 1:
            print(colors.warn(
                "check on multiple targets: probing only " + targets[0] +
                " (use 'run' to scan all " + str(len(targets)) + ")"
            ))
        host = targets[0]
        print(colors.info("check: probing " + self._base_url(host)))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        sem = asyncio.Semaphore(1)
        r = loop.run_until_complete(self._probe_async(host, sem))
        loop.close()

        if r.detected:
            ver = " v" + r.version if r.version else ""
            print(colors.good("check: " + host + " — MikroTik RouterOS detected" + ver))
            print(colors.dimmed("  indicators: " + ", ".join(r.matched)))
            return CheckResult.UNKNOWN

        if r.error:
            print(colors.safe("check: " + host + " not detected (" + r.error + ")"))
        else:
            print(colors.safe("check: " + host + " no RouterOS indicators found"))
        return CheckResult.SAFE

    def action(self):
        targets = self._expand_targets()

        print(colors.info("scanning " + str(len(targets)) +
                          " host(s) with " + str(self.options["THREADS"]) +
                          " concurrent requests"))

        bar = ProgressBar(total=len(targets), prefix="scan")

        try:
            hits = self._phase_async(targets, bar)
        except Exception as e:
            print(colors.bad("asyncio error: " + type(e).__name__))
            return []
        finally:
            bar.done()

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        if workspace_active:
            for h in hits:
                self._record_host_result(h)

        errors = len(targets) - len(hits)

        print()
        print(colors.heading("--- HTTP detection summary ---"))
        print("  targets:      " + str(len(targets)))
        print("  RouterOS:     " + colors.green(str(len(hits))))
        print("  errors/skips: " + colors.dimmed(str(errors)))
        if workspace_active and hits:
            ws = db.current_workspace()
            print("  recorded:     " + colors.dimmed(
                f"{len(hits)} host(s), {len(hits)} service(s), "
                f"{len(hits)} note(s) in workspace '{ws}'"
            ))

        if hits:
            print(colors.heading("  detected hosts:"))
            for h in hits:
                ver = " v" + h.version if h.version else ""
                print("    " + colors.good(h.host) + "  " +
                      colors.dimmed("[RouterOS]" + ver))

        return hits
