import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET


class NmapNotFound(RuntimeError):
    pass


class NmapParseError(RuntimeError):
    pass


OUTPUT_FLAGS = ("-oX", "-oN", "-oG", "-oA", "-oS", "-oM")


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def strip_output_flags(args: str) -> str:
    return " ".join(
        a for a in args.split()
        if not any(a == f or a.startswith(f) for f in OUTPUT_FLAGS)
    )


def _repair_truncated_xml(xml: str) -> str | None:
    if "</nmaprun>" in xml:
        return None

    start = xml.find("<nmaprun")
    if start == -1:
        return None

    opener_end = xml.find(">", start)
    if opener_end == -1:
        return None

    last_host_end = xml.rfind("</host>")
    if last_host_end == -1:
        return None

    body = xml[start:last_host_end + len("</host>")]
    return body + "\n</nmaprun>"


def run_nmap(args: str, timeout: float = 3600.0) -> str:
    if not nmap_available():
        raise NmapNotFound("nmap not found on PATH")

    cleaned = strip_output_flags(args)

    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="metis_nmap_")
    os.close(fd)

    try:
        cmd = ["nmap"] + cleaned.split() + ["-oX", xml_path]
        proc = subprocess.Popen(cmd)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        except KeyboardInterrupt:
            print()
            print("[*] nmap: interrupt received, waiting for graceful shutdown...")
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        if not os.path.isfile(xml_path):
            raise NmapParseError("nmap produced no XML output")

        try:
            with open(xml_path, "r", errors="replace") as f:
                xml = f.read()
        except OSError as e:
            raise NmapParseError(f"could not read nmap XML: {e}")

        if not xml.strip():
            raise NmapParseError("nmap XML output was empty")

        return xml
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def parse_nmap_xml(xml_text: str) -> dict:
    repaired = False

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        fixed = _repair_truncated_xml(xml_text)
        if not fixed:
            raise NmapParseError(f"invalid nmap XML: {e}")
        try:
            root = ET.fromstring(fixed)
            repaired = True
        except ET.ParseError:
            raise NmapParseError(
                f"invalid nmap XML: {e} (file appears truncated and could not be repaired)"
            )

    if root.tag != "nmaprun":
        raise NmapParseError(f"unexpected root tag: {root.tag}")

    command = root.get("args", "")
    out = {"hosts": [], "runstats": {}, "command": command, "repaired": repaired}

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is None or status_el.get("state") != "up":
            continue

        address = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                address = addr_el.get("addr", "")
                break
        if not address:
            continue

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        os_name = ""
        os_accuracy = 0
        os_info = ""
        os_el = host_el.find("os")
        if os_el is not None:
            matches = os_el.findall("osmatch")
            if matches:
                best = max(matches, key=lambda m: int(m.get("accuracy", "0")))
                os_name = best.get("name", "")
                os_accuracy = int(best.get("accuracy", "0"))
                osclasses = best.findall("osclass")
                if osclasses:
                    parts = []
                    for oc in osclasses[:2]:
                        vendor = oc.get("vendor", "")
                        family = oc.get("osfamily", "")
                        gen = oc.get("osgen", "")
                        if family:
                            parts.append(f"{vendor} {family} {gen}".strip())
                    os_info = " | ".join(parts)

        services = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None:
                    continue
                pstate = state_el.get("state", "unknown")
                if pstate not in ("open", "open|filtered"):
                    continue

                port_num = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")

                svc_el = port_el.find("service")
                name = ""
                product = ""
                version = ""
                extrainfo = ""
                banner = ""
                cpes = []
                if svc_el is not None:
                    name = svc_el.get("name", "")
                    product = svc_el.get("product", "")
                    version = svc_el.get("version", "")
                    extrainfo = svc_el.get("extrainfo", "")
                    banner = svc_el.get("ostype", "")
                    cpes = [c.text for c in svc_el.findall("cpe") if c.text]

                scripts = []
                for script_el in port_el.findall("script"):
                    scripts.append({
                        "id": script_el.get("id", ""),
                        "output": (script_el.get("output") or "").strip(),
                    })

                services.append({
                    "port": port_num,
                    "proto": proto,
                    "state": pstate,
                    "name": name,
                    "product": product,
                    "version": version,
                    "banner": banner,
                    "extrainfo": extrainfo,
                    "cpe": cpes,
                    "scripts": scripts,
                })

        host_scripts = []
        for script_el in host_el.findall("hostscript"):
            scripts_el = script_el.find("script")
            if scripts_el is not None:
                host_scripts.append({
                    "id": scripts_el.get("id", ""),
                    "output": (scripts_el.get("output") or "").strip(),
                })

        out["hosts"].append({
            "address": address,
            "hostname": hostname,
            "state": "up",
            "os": os_name,
            "os_accuracy": os_accuracy,
            "info": os_info,
            "services": services,
            "scripts": host_scripts,
        })

    rs = root.find("runstats")
    if rs is not None:
        finished = rs.find("finished")
        if finished is not None:
            out["runstats"] = {
                "time": finished.get("time", ""),
                "elapsed": float(finished.get("elapsed", "0")),
                "exit": finished.get("exit", ""),
                "summary": finished.get("summary", ""),
            }

    return out


def import_to_db(db, parsed: dict) -> dict:
    counts = {"hosts": 0, "services": 0, "notes": 0, "events": 0}

    if db.current_workspace_id() is None:
        raise RuntimeError("no active workspace")

    for h in parsed["hosts"]:
        addr = h["address"]

        host_fields = {"state": "up"}
        if h.get("hostname"):
            host_fields["name"] = h["hostname"]
        if h.get("os"):
            host_fields["os"] = h["os"]
        if h.get("info"):
            host_fields["info"] = h["info"]

        try:
            db.ensure_host(addr, **host_fields)
            counts["hosts"] += 1
        except Exception:
            continue

        if h.get("os"):
            note = "os=" + h["os"]
            if h.get("os_accuracy"):
                note += f" accuracy={h['os_accuracy']}%"
            if h.get("info"):
                note += " | " + h["info"]
            try:
                db.add_note(note, host_address=addr, kind="nmap_os")
                counts["notes"] += 1
            except Exception:
                pass

        for sc in h.get("scripts", []):
            if not sc.get("output"):
                continue
            try:
                db.add_note(
                    f"{sc['id']}: {sc['output'][:500]}",
                    host_address=addr,
                    kind="nmap_script",
                )
                counts["notes"] += 1
            except Exception:
                pass

        for svc in h.get("services", []):
            banner_parts = []
            if svc.get("product"):
                banner_parts.append(svc["product"])
            if svc.get("version"):
                banner_parts.append(svc["version"])
            if svc.get("extrainfo"):
                banner_parts.append(svc["extrainfo"])
            banner = " ".join(banner_parts)[:200]

            try:
                db.add_service(
                    addr,
                    svc["port"],
                    proto=svc["proto"],
                    name=svc.get("name", ""),
                    state=svc.get("state", "open"),
                    banner=banner,
                )
                counts["services"] += 1
            except Exception:
                pass

            for sc in svc.get("scripts", []):
                if not sc.get("output"):
                    continue
                try:
                    db.add_note(
                        f"{svc['proto']}/{svc['port']} {sc['id']}: {sc['output'][:500]}",
                        host_address=addr,
                        kind="nmap_script",
                    )
                    counts["notes"] += 1
                except Exception:
                    pass

    cmd = parsed.get("command", "")
    elapsed = parsed.get("runstats", {}).get("elapsed", 0)
    repaired_note = " (partial)" if parsed.get("repaired") else ""
    try:
        db.log_event(
            f"nmap: {len(parsed['hosts'])} host(s), "
            f"{counts['services']} service(s), {elapsed:.1f}s{repaired_note} | {cmd[:120]}",
            kind="nmap",
        )
        counts["events"] += 1
    except Exception:
        pass

    return counts
