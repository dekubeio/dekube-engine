"""Public helper functions available to extensions."""

import base64
import fnmatch
import secrets
import string
import sys


def apply_replacements(text: str, replacements: list[dict]) -> str:
    """Apply user-defined string replacements from config.

    Malformed entries (not a mapping, or missing ``old``) are skipped rather
    than crashing the run — ``replacements`` is a user-edited config field.
    """
    for r in (replacements or []):
        if not isinstance(r, dict) or "old" not in r:
            continue
        text = text.replace(r["old"], r.get("new") or "")
    return text


def secret_value(secret: dict, key: str) -> str | None:
    """Get a decoded value from a K8s Secret (base64 data or plain stringData)."""
    # stringData is plain text (rare in rendered output, but possible)
    val = (secret.get("stringData") or {}).get(key)
    if val is not None:
        return val
    # data is base64-encoded
    val = (secret.get("data") or {}).get(key)
    if val is not None:
        try:
            return base64.b64decode(val).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return val  # fallback: return raw if decode fails
    return None


# Backward compat alias (deprecated)
_secret_value = secret_value


def log(name: str, msg: str) -> None:
    """Print an extension log line to stderr: ``  [name] msg``."""
    print(f"  [{name}] {msg}", file=sys.stderr)


def generate_password(length: int = 24) -> str:
    """Generate a random alphanumeric password."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def is_excluded(name: str, patterns: list[str]) -> bool:
    """True if ``name`` matches any fnmatch pattern in ``patterns`` (null-safe)."""
    return any(fnmatch.fnmatch(name, pat) for pat in (patterns or []))
