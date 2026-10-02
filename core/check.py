class CheckResult:
    VULNERABLE = "vulnerable"
    SAFE       = "safe"
    UNKNOWN    = "unknown"

    @staticmethod
    def colorize(result: str) -> str:
        from core import colors
        if result == CheckResult.VULNERABLE:
            return colors.vuln(result)
        if result == CheckResult.SAFE:
            return colors.safe(result)
        return colors.unknown(result)
