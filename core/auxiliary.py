from core import colors
from core.module import Module


class Auxiliary(Module):
    """Non-session modules: scanners, fuzzers, brute forcers."""

    def run(self):
        try:
            self.load_source()
        except (FileNotFoundError, ValueError) as e:
            raise ValueError(f"SOURCE load failed: {e}")

        missing = self.required_missing()
        if missing:
            raise ValueError(f"missing required options: {', '.join(missing)}")
        return self.action()

    def action(self):
        raise NotImplementedError
