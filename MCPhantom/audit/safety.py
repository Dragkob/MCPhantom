"""Scan safety helpers to avoid destructive MCP operations during auditing."""

# When True (default), AutoPwn avoids writes, static-resource SQLi, and heavy DB load.
SAFE_MODE = True

# Gentle SQLi: sequential probes only, stop after first confirmed hit.
SQLI_SAFE_MAX_PARALLEL = 1
SQLI_PAYLOAD_DELAY_SEC = 0.4
MAX_PARALLEL_CHECKS_SAFE = 2

# Read-only SQLi probes (SELECT / error / boolean). No schema dumps or write verbs.
SAFE_SQLI_PAYLOAD_VALUES = (
    "'",
    "x'--",
    "x'#",
    "x' UNION SELECT 1--",
    "x' UNION SELECT @@version#",
    "x' UNION SELECT sqlite_version()--",
    "1' OR '1'='1'#",
)

MUTATING_TOOL_KEYWORDS = (
    "store",
    "write",
    "save",
    "upload",
    "create",
    "update",
    "delete",
    "remove",
    "insert",
    "put",
    "append",
    "modify",
    "patch",
    "drop",
)


def is_mutating_tool(capability):
    if getattr(capability, "type", "") != "tool":
        return False

    text = " ".join(
        part
        for part in (
            getattr(capability, "name", ""),
            getattr(capability, "description", ""),
        )
        if part
    ).lower()

    return any(keyword in text for keyword in MUTATING_TOOL_KEYWORDS)


def parallel_check_limit():
    if SAFE_MODE:
        return MAX_PARALLEL_CHECKS_SAFE
    return 4


def sqli_parallel_limit():
    if SAFE_MODE:
        return SQLI_SAFE_MAX_PARALLEL
    return 6


def filter_sqli_payloads_safe(payloads):
    """Keep only read-only SQLi probes in safe mode."""
    allowed = set(SAFE_SQLI_PAYLOAD_VALUES)
    picked = [item for item in payloads if item.value in allowed]
    if picked:
        return picked
    return [item for item in payloads if item.value != "1"][:6]


def sqli_payload_cap():
    if SAFE_MODE:
        return None
    return None
