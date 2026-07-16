"""Public contracts for extensions — the sacred pacts."""

from dekube.pacts.types import (
    ConvertContext, ConverterResult, ProviderResult,
    ConvertResult,  # deprecated alias
    Converter, IndexerConverter, Provider,
)
from dekube.pacts.ingress import IngressRewriter, get_ingress_class, resolve_backend
from dekube.pacts.helpers import (
    apply_replacements, secret_value, log, generate_password, is_excluded,
    iter_workloads, iter_named_containers, apply_alias_map, rewrite_k8s_dns,
    write_configmap_files, write_secret_files,
)
from dekube.core.env import resolve_env

# Backward compat alias (deprecated — use secret_value)
_secret_value = secret_value

__all__ = [
    "ConvertContext",
    "ConverterResult",
    "ProviderResult",
    "ConvertResult",
    "Converter",
    "IndexerConverter",
    "Provider",
    "IngressRewriter",
    "get_ingress_class",
    "resolve_backend",
    "apply_replacements",
    "resolve_env",
    "secret_value",
    "log",
    "generate_password",
    "is_excluded",
    "iter_workloads",
    "iter_named_containers",
    "apply_alias_map",
    "rewrite_k8s_dns",
    "write_configmap_files",
    "write_secret_files",
    "_secret_value",
]
