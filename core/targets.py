import ipaddress
from pathlib import Path

class TargetParseError(ValueError):
    pass

def _expand_one(token: str) -> list[str]:
    token = token.strip()
    if not token:
        return []

    if "-" in token and "/" not in token:
        lo, _, hi = token.partition("-")
        try:
            start = ipaddress.ip_address(lo.strip())
            end = ipaddress.ip_address(hi.strip())
        except ValueError:
            return [token]
        if start.version != end.version:
            raise TargetParseError(f"range mixes IPv4 and IPv6: {token}")
        out = []
        cur, last = int(start), int(end)
        if cur > last:
            cur, last = last, cur
        while cur <= last:
            out.append(str(ipaddress.ip_address(cur)))
            cur += 1
        return out

    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as e:
            raise TargetParseError(f"bad CIDR {token!r}: {e}")
        return [str(ip) for ip in net.hosts()]

    return [token]

def _read_file(path: str) -> list[str]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise TargetParseError(f"targets file not found: {p}")
    tokens = []
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for part in line.split(","):
            part = part.strip()
            if part and not part.startswith("#"):
                tokens.append(part)
    return tokens

def parse_targets(spec: str | None) -> list[str]:
    if spec is None:
        return []
    spec = str(spec).strip()
    if not spec:
        return []

    raw_tokens: list[str] = []

    if spec.startswith("file:"):
        raw_tokens.extend(_read_file(spec[len("file:"):].strip()))
    else:
        for chunk in spec.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if chunk.startswith("file:"):
                raw_tokens.extend(_read_file(chunk[len("file:"):].strip()))
            else:
                raw_tokens.append(chunk)

    seen, out = set(), []
    for tok in raw_tokens:
        for host in _expand_one(tok):
            if host not in seen:
                seen.add(host)
                out.append(host)
    return out

def summarise(targets: list[str]) -> str:
    if not targets:
        return "0 hosts"
    if len(targets) == 1:
        return f"1 host ({targets[0]})"
    return f"{len(targets)} hosts"
