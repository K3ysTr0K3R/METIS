import os
import re
import sys
import threading
import time

def _colorize(slot: str, text: str) -> str:
    try:
        from core import colors
        return colors.wrap(slot)(text)
    except Exception:
        return text

def _gradient_stops():
    try:
        from core import colors
        return colors.gradient_stops()
    except Exception:
        return [51, 45, 39, 135, 171, 201]

class ProgressBar:
    def __init__(self, total: int, prefix: str = "", width: int = 30,
                 stream=None, redraw_hz: float = 10.0,
                 gradient: bool = True):
        self.total = max(int(total), 1)
        self.prefix = prefix
        self.width = width
        self.stream = stream or sys.stderr
        self.min_interval = 1.0 / max(redraw_hz, 0.1)
        self.gradient = gradient

        self.count = 0
        self.start = time.time()
        self._last_render = 0.0
        self._lock = threading.RLock()
        self._last_len = 0

        self._enabled = (
            not os.environ.get("NO_COLOR")
            and hasattr(self.stream, "isatty")
            and self.stream.isatty()
        )

    def tick(self, n: int = 1):
        with self._lock:
            self.count += n
            now = time.time()
            if self._enabled and (now - self._last_render) >= self.min_interval:
                self._render_locked()
                self._last_render = now
            elif self._enabled and self.count >= self.total:
                self._render_locked()
                self._last_render = now

    def log(self, msg: str):
        with self._lock:
            if not self._enabled:
                print(msg, file=self.stream)
                return
            self._clear_locked()
            self.stream.write(msg + "\n")
            self._render_locked()
            self.stream.flush()

    def _pick_stop(self, stops: list[int], pos: float) -> int:
        """Given a 0..1 position and a list of stops, return the nearest stop."""
        if not stops:
            return 51
        if len(stops) == 1:
            return stops[0]
        idx = pos * (len(stops) - 1)
        lo = int(idx)
        if lo >= len(stops) - 1:
            return stops[-1]
        frac = idx - lo
        return stops[lo] if frac < 0.5 else stops[lo + 1]

    def _build_bar(self) -> str:
        frac = min(self.count / self.total, 1.0)
        filled = int(self.width * frac)

        filled_ch = "█"
        empty_ch = "░"

        if not self._enabled:
            return filled_ch * filled + empty_ch * (self.width - filled)

        if self.gradient and filled > 0:
            stops = _gradient_stops()
            chunks = []
            for i in range(filled):
                pos = i / max(filled - 1, 1)
                code = self._pick_stop(stops, pos)
                chunks.append(f"\033[38;5;{code}m{filled_ch}\033[0m")
            filled_str = "".join(chunks)
        else:
            filled_str = _colorize("good", filled_ch * filled)

        empty_str = _colorize("dim", empty_ch * (self.width - filled))
        return filled_str + empty_str

    def _build_line(self) -> str:
        frac = min(self.count / self.total, 1.0)
        bar = self._build_bar()
        pct = frac * 100
        elapsed = time.time() - self.start
        rate = self.count / elapsed if elapsed > 0 else 0
        eta = (self.total - self.count) / rate if rate > 0 else 0

        prefix_txt = _colorize("info", self.prefix) if self._enabled else self.prefix
        pct_txt = _colorize("good", f"{pct:5.1f}%") if self._enabled else f"{pct:5.1f}%"
        count_txt = f"{self.count}/{self.total}"
        rate_txt = f"{rate:5.1f}/s"
        eta_txt = f"ETA {eta:4.0f}s"

        if self._enabled:
            count_txt = _colorize("session", count_txt)
            rate_txt = _colorize("dim", rate_txt)
            eta_txt = _colorize("dim", eta_txt)

        return (
            f"  {prefix_txt} [{bar}] {pct_txt}  "
            f"{count_txt}  {rate_txt}  {eta_txt}"
        )

    def _clear_locked(self):
        self.stream.write("\r" + (" " * self._last_len) + "\r")

    def _render_locked(self):
        line = self._build_line()
        self._last_len = self._visible_len(line)
        self.stream.write("\r" + line)
        self.stream.flush()

    @staticmethod
    def _visible_len(s: str) -> int:
        return len(re.sub(r"\x1b\[[0-9;]*m", "", s))

    def done(self):
        with self._lock:
            if not self._enabled:
                return
            self._render_locked()
            self.stream.write("\n")
            self.stream.flush()
