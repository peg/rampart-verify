"""Redact secrets from command strings before sending to LLM providers.

The LLM only needs to classify intent — it never needs actual secret values.
This module strips common secret patterns and replaces them with [REDACTED].
"""

import re
from typing import Dict, Any

# Patterns that match common secret formats.
# Order matters — more specific patterns first to avoid partial matches.
SECRET_PATTERNS = [
    # AWS keys
    (r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_KEY]'),
    (r'(?i)(aws_secret_access_key|aws_session_token)[=:]\s*\S+', r'\1=[REDACTED]'),

    # Stripe keys (before generic sk- pattern)
    (r'(?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{10,}', '[REDACTED_STRIPE_KEY]'),

    # OpenAI / Anthropic / common API keys
    (r'sk-ant-[a-zA-Z0-9_-]{20,}', '[REDACTED_API_KEY]'),
    (r'sk-proj-[a-zA-Z0-9_-]{20,}', '[REDACTED_API_KEY]'),
    (r'sk-[a-zA-Z0-9_-]{20,}', '[REDACTED_API_KEY]'),

    # GitHub tokens
    (r'ghp_[a-zA-Z0-9]{36}', '[REDACTED_GH_TOKEN]'),
    (r'gho_[a-zA-Z0-9]{36}', '[REDACTED_GH_TOKEN]'),
    (r'ghu_[a-zA-Z0-9]{36}', '[REDACTED_GH_TOKEN]'),
    (r'ghs_[a-zA-Z0-9]{36}', '[REDACTED_GH_TOKEN]'),
    (r'github_pat_[a-zA-Z0-9_]{22,}', '[REDACTED_GH_TOKEN]'),

    # Bearer / Authorization headers
    (r'(?i)(bearer\s+)\S+', r'\1[REDACTED]'),
    (r'(?i)(authorization:\s*(?:bearer|basic|token)\s+)\S+', r'\1[REDACTED]'),

    # Basic auth in URLs (user:pass@host)
    (r'(https?://)([^:]+):([^@]+)@', r'\1\2:[REDACTED]@'),

    # Generic key=value patterns for common secret env vars
    (r'(?i)(api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd|pwd)[=:]\s*\S+', r'\1=[REDACTED]'),

    # Hex strings that look like tokens (32+ hex chars)
    (r'(?<![a-zA-Z0-9])[0-9a-f]{40,}(?![a-zA-Z0-9])', '[REDACTED_HEX]'),

    # Base64-encoded blobs in header values (after -H flag, 40+ chars)
    (r'(-H\s+["\'][^"\']*:\s*)[A-Za-z0-9+/=]{40,}', r'\1[REDACTED_B64]'),
]

# Compile patterns once at import time.
_COMPILED = [(re.compile(pattern), replacement) for pattern, replacement in SECRET_PATTERNS]


def redact_secrets(text: str) -> str:
    """Replace secret-like patterns in text with redaction placeholders.

    The goal is to remove actual secret values while preserving enough
    structure for the LLM to classify the command's intent.
    """
    if not text:
        return text

    result = text
    for pattern, replacement in _COMPILED:
        result = pattern.sub(replacement, result)

    return result


def redact_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of params with secrets redacted from string values.

    Only processes top-level string values and known nested keys.
    Does NOT modify the original dict.
    """
    redacted = {}
    for key, value in params.items():
        if isinstance(value, str):
            redacted[key] = redact_secrets(value)
        elif isinstance(value, dict):
            redacted[key] = {
                k: redact_secrets(v) if isinstance(v, str) else v
                for k, v in value.items()
            }
        else:
            redacted[key] = value
    return redacted
