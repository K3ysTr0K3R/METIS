import os
import sys

from core.themes import THEMES, DEFAULT_THEME


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_ENABLED = _supports_color()
_current_theme = os.environ.get("METIS_THEME", DEFAULT_THEME)
if _current_theme not in THEMES:
    _current_theme = DEFAULT_THEME


def _code(key: str) -> str:
    palette = THEMES.get(_current_theme, THEMES[DEFAULT_THEME])
    return palette.get(key, THEMES[DEFAULT_THEME].get(key, "0"))


def _wrap(key: str):
    def f(s):
        if not _ENABLED:
            return str(s)
        return f"\033[{_code(key)}m{s}\033[0m"
    return f


def info(msg):    return _wrap("info")(f"[*] {msg}")
def good(msg):    return _wrap("good")(f"[+] {msg}")
def warn(msg):    return _wrap("warn")(f"[!] {msg}")
def bad(msg):     return _wrap("bad")(f"[-] {msg}")
def vuln(msg):    return _wrap("vuln")(f"[VULNERABLE] {msg}")
def safe(msg):    return _wrap("safe")(f"[SAFE] {msg}")
def unknown(msg): return _wrap("unknown")(f"[UNKNOWN] {msg}")
def dimmed(msg):  return _wrap("dim")(msg)
def heading(msg): return _wrap("heading")(msg)
def accent(msg):  return _wrap("accent")(msg)
def session(msg): return _wrap("session")(msg)


red     = _wrap("bad")
green   = _wrap("good")
yellow  = _wrap("warn")
blue    = _wrap("info")
magenta = _wrap("accent")
cyan    = _wrap("session")
white   = lambda s: str(s)
dim     = _wrap("dim")


def bold(s):
    if not _ENABLED:
        return str(s)
    return f"\033[1m{s}\033[0m"


def set_theme(name: str) -> bool:
    global _current_theme
    if name not in THEMES:
        return False
    _current_theme = name
    return True


def current_theme() -> str:
    return _current_theme


def list_themes() -> list[str]:
    return sorted(THEMES.keys())


def theme_preview(name: str) -> str:
    global _current_theme
    prev = _current_theme
    _current_theme = name
    try:
        sample = (
            f"{info('info')}  {good('good')}  {warn('warn')}  "
            f"{bad('bad')}  {vuln('vulnerable')}  {dimmed('dim')}  "
            f"{heading('heading')}  {accent('accent')}"
        )
    finally:
        _current_theme = prev
    return sample


def wrap(key: str):
    return _wrap(key)


def wrap_fallback(key: str, fallback_key: str):
    palette = THEMES.get(_current_theme, THEMES[DEFAULT_THEME])
    code = palette.get(key)
    if code is None:
        code = palette.get(fallback_key, THEMES[DEFAULT_THEME].get(fallback_key, "0"))
    def f(s):
        if not _ENABLED:
            return str(s)
        return f"\033[{code}m{s}\033[0m"
    return f


DEFAULT_GRADIENT = [51, 45, 39, 135, 171, 201]


def gradient_stops() -> list[int]:
    palette = THEMES.get(_current_theme, THEMES[DEFAULT_THEME])
    stops = palette.get("bar_gradient")
    if not stops:
        stops = list(DEFAULT_GRADIENT)
    return list(stops)


def set_gradient(stops: list[int]) -> bool:
    if not stops or len(stops) < 2:
        return False
    if not all(isinstance(c, int) and 0 <= c <= 255 for c in stops):
        return False
    palette = THEMES.setdefault(_current_theme, {})
    palette["bar_gradient"] = list(stops)
    return True


def reset_gradient() -> bool:
    palette = THEMES.get(_current_theme)
    if not palette or "bar_gradient" not in palette:
        return False
    del palette["bar_gradient"]
    return True


def ansi(code: str, text: str) -> str:
    if not _ENABLED:
        return str(text)
    return f"\033[{code}m{text}\033[0m"


def strip_ansi(s: str) -> str:
    import re
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def enabled() -> bool:
    return _ENABLED
