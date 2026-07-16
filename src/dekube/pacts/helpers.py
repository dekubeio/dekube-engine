"""Public helper functions available to extensions."""

import base64
import fnmatch
import re
import secrets
import string
import sys
from collections.abc import Iterator

from dekube.core.constants import WORKLOAD_KINDS, _K8S_DNS_RE


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


def iter_workloads(manifests: dict) -> Iterator[tuple[str, dict]]:
    """Yield (workload_name, pod_spec) for every workload manifest (null-safe)."""
    for kind in WORKLOAD_KINDS:
        for m in manifests.get(kind) or []:
            if not m:
                continue
            name = (m.get("metadata") or {}).get("name", "unknown")
            spec = m.get("spec") or {}
            pod_spec = spec if kind == "Pod" else (spec.get("template") or {}).get("spec") or {}
            yield name, pod_spec


def iter_named_containers(name: str, pod_spec: dict) -> Iterator[tuple[str, dict]]:
    """Yield (compose_service_name, container) for main, init and sidecar containers.

    Naming matches the workload converter: main -> name,
    init -> "<name>-init-<cname>", sidecar -> "<name>-sidecar-<cname>".
    """
    containers = pod_spec.get("containers") or []
    if containers and containers[0]:
        yield name, containers[0]
    for ic in pod_spec.get("initContainers") or []:
        if ic:
            yield f"{name}-init-{ic.get('name', 'init')}", ic
    for sc in containers[1:]:
        if sc:
            yield f"{name}-sidecar-{sc.get('name', 'sidecar')}", sc


def apply_alias_map(text: str, alias_map: dict[str, str]) -> str:
    """Replace K8s Service names with compose service names in hostname positions.

    Matches aliases preceded by / or @ (URLs, Redis URIs) and followed by
    / : whitespace, quotes, or end-of-string — so only hostnames are affected,
    not substrings like bucket names.
    """
    for alias, target in (alias_map or {}).items():
        text = re.sub(r'(?<=[/@])' + re.escape(alias) + r'''(?=[/:\s"']|$)''', target, text)
    return text


def rewrite_k8s_dns(text: str) -> str:
    """Replace <svc>.<ns>.svc[.cluster.local] with just <svc>."""
    return _K8S_DNS_RE.sub(r'\1', text)


def write_configmap_files(name: str, ctx, items: list | None = None) -> str | None:
    """Emit a ConfigMap's data as files under output_dir/configmaps/<name>/.

    Returns the relative dir (``./configmaps/<name>``) or None (+ ctx.warnings) if absent.
    """
    from dekube.core.volumes import _generate_configmap_files  # local: avoid import cycle
    cm = ctx.configmaps.get(name)
    if cm is None:
        ctx.warnings.append(f"ConfigMap '{name}' not found")
        return None
    return _generate_configmap_files(
        name, cm.get("data") or {}, ctx.output_dir, ctx.generated_cms, ctx.warnings,
        binary_data=cm.get("binaryData") or {}, items=items,
    )


def write_secret_files(name: str, ctx, items: list | None = None) -> str | None:
    """Emit a Secret's data as files under output_dir/secrets/<name>/.

    Returns the relative dir (``./secrets/<name>``) or None (+ ctx.warnings) if absent.
    """
    from dekube.core.volumes import _generate_secret_files  # local: avoid import cycle
    sec = ctx.secrets.get(name)
    if sec is None:
        ctx.warnings.append(f"Secret '{name}' not found")
        return None
    return _generate_secret_files(
        name, sec, items, ctx.output_dir, ctx.generated_secrets, ctx.warnings,
    )
