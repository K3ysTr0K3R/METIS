from concurrent.futures import ThreadPoolExecutor, as_completed

from core import colors
from core.auxiliary import Auxiliary
from core.check import CheckResult
from core.module import Option
from core.progress import ProgressBar


class AutoCheck(Auxiliary):
    NAME = "AutoCheck"
    DESCRIPTION = (
        "Runs every CVE auxiliary module's check() against the target(s) and "
        "reports which ones are vulnerable. Records every VULNERABLE result "
        "into the active workspace. Check-only — does not run exploit() or "
        "action()."
    )
    AUTHOR = "K3ysTr0K3R"
    RANK = "excellent"
    CHECK = False

    OPTIONS = [
        Option("RHOSTS", required=True,
               description="target(s): host | h1,h2 | CIDR | range | file:path"),
        Option("THREADS", default=20, type=int,
               description="concurrent (module, host) checks"),
        Option("INCLUDE_SELF", default=False, type=bool,
               description="include this module in the sweep (skip by default)"),
        Option("ONLY", default="",
               description="extra substring filter on top of the cve filter"),
        Option("SKIP", default="",
               description="skip modules whose path contains this substring"),
        Option("STOP_ON_FIRST", default=False, type=bool,
               description="stop after first VULNERABLE module (per target)"),
        Option("VERBOSE", default=False, type=bool,
               description="print per-module SAFE/UNKNOWN results too"),
    ]

    def _expand_targets(self):
        hosts = self.resolve_targets()
        if not hosts:
            raise ValueError("no targets - set RHOSTS")
        if len(hosts) > 1:
            print(colors.info("target list -> " + str(len(hosts)) + " hosts"))
        return hosts

    def _auxiliary_modules(self):
        if not self.framework:
            return []
        paths = []
        for path in self.framework.modules.list():
            if not path.startswith("auxiliary/"):
                continue
            if "cve" not in path.lower():
                continue
            if path == "auxiliary/scanner/autocheck":
                if not self.options["INCLUDE_SELF"]:
                    continue
            paths.append(path)

        only = (self.options["ONLY"] or "").strip()
        skip = (self.options["SKIP"] or "").strip()
        if only:
            paths = [p for p in paths if only in p]
        if skip:
            paths = [p for p in paths if skip not in p]

        return sorted(paths)

    def _check_module(self, module_path, target):
        try:
            module = self.framework.modules.get(module_path)
        except KeyError:
            return CheckResult.UNKNOWN, "could not load module"
        except Exception as e:
            return CheckResult.UNKNOWN, f"{type(e).__name__}: {e}"

        module.framework = self.framework

        if "RHOSTS" in module.options:
            try:
                module.set_option("RHOSTS", target)
            except (TypeError, ValueError) as e:
                return CheckResult.UNKNOWN, f"bad RHOSTS: {e}"
        elif "RHOST" in module.options:
            try:
                module.set_option("RHOST", target)
            except (TypeError, ValueError) as e:
                return CheckResult.UNKNOWN, f"bad RHOST: {e}"
        else:
            return CheckResult.UNKNOWN, "module has no RHOST/RHOSTS"

        missing = module.required_missing()
        if missing:
            return CheckResult.UNKNOWN, "missing required options: " + ", ".join(missing)

        if not self._supports_check(module):
            return CheckResult.UNKNOWN, "no check() implemented"

        try:
            result = module.check()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            return CheckResult.UNKNOWN, f"{type(e).__name__}: {e}"

        return result, ""

    @staticmethod
    def _supports_check(module):
        from core.module import Module
        check_fn = getattr(module, "check", None)
        if check_fn is None:
            return False
        if type(module).check is Module.check:
            return False
        return True

    def _record_vuln(self, module_path, target):
        db = self._db()
        if not db:
            return
        if not db.current_workspace_id():
            return
        try:
            module = self.framework.modules.get(module_path)
            name = getattr(module, "NAME", "") or module_path
            refs = ",".join(getattr(module, "REFERENCES", []) or [])
            db.ensure_host(target, state="up")
            db.add_vuln(
                name=name,
                module=module_path,
                host_address=target,
                severity="unknown",
                refs=refs,
                info="autocheck: check() returned vulnerable",
            )
        except Exception:
            pass

    def action(self):
        targets = self._expand_targets()
        module_paths = self._auxiliary_modules()

        if not module_paths:
            print(colors.warn("no CVE auxiliary modules available to check"))
            return []

        total = len(module_paths) * len(targets)
        threads = max(1, self.options["THREADS"])

        print(colors.info(
            f"autocheck: {len(module_paths)} CVE module(s) "
            f"against {len(targets)} host(s)"
        ))
        print(colors.dimmed(
            f"  total check() calls: {total}  |  threads: {threads}"
        ))

        only = (self.options["ONLY"] or "").strip()
        skip = (self.options["SKIP"] or "").strip()
        if only:
            print(colors.dimmed(f"  filter ONLY={only!r}"))
        if skip:
            print(colors.dimmed(f"  filter SKIP={skip!r}"))

        stop_first = self.options["STOP_ON_FIRST"]
        verbose = self.options["VERBOSE"]

        db = self._db()
        workspace_active = bool(db and db.current_workspace_id())

        hits = []
        safe_count = 0
        unknown_count = 0
        error_count = 0
        check_count = 0
        stopped_targets = set()

        bar = ProgressBar(total=total, prefix="autocheck")

        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {}
                for target in targets:
                    for module_path in module_paths:
                        if stop_first and target in stopped_targets:
                            continue
                        fut = ex.submit(self._check_module, module_path, target)
                        futures[fut] = (module_path, target)

                for fut in as_completed(futures):
                    module_path, target = futures[fut]
                    check_count += 1
                    bar.tick()

                    try:
                        result, detail = fut.result()
                    except Exception as e:
                        result = CheckResult.UNKNOWN
                        detail = f"{type(e).__name__}: {e}"

                    if result == CheckResult.VULNERABLE:
                        hits.append({
                            "host": target,
                            "module": module_path,
                            "detail": detail,
                        })
                        bar.log(
                            f"{colors.vuln('VULN')}  "
                            f"{colors.good(target)}  "
                            f"{colors.session(module_path)}"
                        )
                        if workspace_active:
                            self._record_vuln(module_path, target)
                        if stop_first:
                            stopped_targets.add(target)

                    elif result == CheckResult.SAFE:
                        safe_count += 1
                        if verbose:
                            bar.log(
                                f"{colors.good('safe')}  {target}  {module_path}"
                            )

                    elif result == CheckResult.UNKNOWN:
                        unknown_count += 1
                        if verbose or (detail and detail != "no check() implemented"):
                            bar.log(
                                f"{colors.warn('unknown')}  {target}  "
                                f"{module_path}  ({detail})"
                            )

                    else:
                        error_count += 1
                        bar.log(
                            f"{colors.bad('error')}  {target}  "
                            f"{module_path}  ({detail})"
                        )
        finally:
            bar.done()

        print()
        print(colors.heading("--- autocheck summary ---"))
        print(f"  hosts:       {len(targets)}")
        print(f"  modules:     {len(module_paths)}")
        print(f"  check calls: {check_count}")
        print(f"  vulnerable:  {colors.green(str(len(hits)))}")
        print(f"  safe:        {colors.dimmed(str(safe_count))}")
        print(f"  unknown:     {colors.warn(str(unknown_count))}")
        print(f"  errors:      {colors.bad(str(error_count))}")

        if workspace_active and hits:
            ws = db.current_workspace()
            print(colors.dimmed(
                f"  recorded {len(hits)} vuln(s) in workspace '{ws}'"
            ))

        if hits:
            print()
            print(colors.heading("  vulnerabilities found:"))
            for h in hits:
                print(f"    {colors.vuln(h['host'])}  {colors.session(h['module'])}")

        return hits
