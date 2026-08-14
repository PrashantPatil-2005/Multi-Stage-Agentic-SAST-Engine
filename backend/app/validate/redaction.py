"""Conservative secret redaction for evidence sent to external LLM providers.

This is deliberately a coarse pattern-based filter, NOT a complete secret
scanner. It lowers the risk of leaking obvious credentials embedded in the
analyzed source; treat it as a first line of defense and audit high-value
repositories separately.
"""

import re

_REDACTED = "<REDACTED:secret>"

#: Pattern order matters: more specific patterns first.
_SECRET_PATTERNS = [
    # -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
    ),
    # API keys / secrets / tokens / passwords / pwd assignments
    re.compile(
        r"(?i)(api[_-]?key|apikey|secret|secret[_-]?key|token|auth[_-]?token|"
        r"access[_-]?key|password|passwd|pwd|db[_-]?password)\b"
        r"\s*[=:]\s*['\"][^'\"]{4,}['\"]"
    ),
    # AWS key pairs
    re.compile(
        r"(?i)(AKIA[0-9A-Z]{16}|aws[_-]?(access[_-]?key|secret[_-]?key)"
        r"['\"]?\s*[=:]\s*['\"][A-Z0-9/+=]{16,}['\"])"
    ),
    # Bearer tokens
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*\b"),
    # Database connection URLs with embedded credentials
    re.compile(
        r"(?i)\b(postgres(?:ql)?|mysql|mssql|sqlite|mongodb|redis|amqp)"
        r"(\+[a-z0-9]+)?://[^'\s\"\\]+"
    ),
    # x-api-key / authorization headers
    re.compile(r"(?i)\b(x-api-key|authorization)\b\s*[=:]\s*['\"][^'\"]{4,}['\"]"),
    # GitHub / Slack tokens
    re.compile(r"\b(ghp|github_pat|xox[baprs]-)[A-Za-z0-9_\-]+"),
]


def redact_secrets(text: str) -> str:
    """Replace credential-looking substrings in ``text`` with a placeholder."""
    if not text:
        return text
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(_REDACTED, result)
    return result
