"""Small encoding helpers used by exploit modules."""

import base64


def to_hex(s: str) -> str:
    """'abc' -> '616263' (no 0x prefix)."""
    return s.encode().hex()


def to_hex_literal(s: str) -> str:
    """'abc' -> '0x616263' (SQL-safe hex literal)."""
    return "0x" + s.encode().hex()


def to_b64(s: str) -> str:
    """'abc' -> 'YWJj'"""
    return base64.b64encode(s.encode()).decode()


def b64_decode(s: str) -> str:
    return base64.b64decode(s).decode(errors="replace")


def sql_quote(s: str) -> str:
    """Escape single quotes for a SQL string literal."""
    return s.replace("'", "''")


def b64_then_hex(s: str) -> str:
    """Two-layer: base64 the string, then hex the b64. Used for SQL-embedded shell cmds."""
    return to_hex_literal(to_b64(s))
