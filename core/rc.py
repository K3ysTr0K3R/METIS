import os
import shlex
from core import colors

def parse_rc_file(path: str) -> list[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"resource file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()

    commands = []
    buffer = ""
    for raw in raw_lines:
        line = raw.rstrip("\n")

        line = _strip_inline_comment(line)
        if not line.strip():
            continue

        if line.rstrip().endswith("\\"):
            buffer += line.rstrip()[:-1] + " "
            continue
        buffer += line
        commands.append(buffer.strip())
        buffer = ""
    if buffer.strip():
        commands.append(buffer.strip())
    return commands

def _strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or line[i - 1].isspace():
                return line[:i]
    return line

def parse_source_file(path: str) -> dict[str, str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"source file not found: {path}")

    opts = {}
    with open(path, "r", encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            if "=" not in line:
                raise ValueError(f"{path}:{n}: missing '=' in '{line}'")
            key, value = line.split("=", 1)
            key = key.strip().upper()
            value = value.strip()

            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            opts[key] = value
    return opts

def execute_rc(console, path: str, echo: bool = True) -> int:
    commands = parse_rc_file(path)
    print(colors.info(f"resource: {path} ({len(commands)} commands)"))

    executed = 0
    for i, line in enumerate(commands, 1):
        if echo:
            print(colors.dimmed(f"  [{i:>3}] {line}"))
        try:
            console.dispatch(line)
            executed += 1
        except Exception as e:
            print(colors.bad(f"  rc line {i} failed: {type(e).__name__}: {e}"))
            break
    print(colors.good(f"resource: executed {executed}/{len(commands)} commands"))
    return executed
