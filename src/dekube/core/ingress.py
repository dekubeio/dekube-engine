"""Ingress conversion — IngressProvider abstract class, rewriter dispatch."""

import sys

from dekube.pacts.types import ConvertContext, ProviderResult, Provider
from dekube.pacts.ingress import IngressRewriter


class _NullRewriter(IngressRewriter):
    """No-op fallback rewriter — returns empty entries."""
    name = "_null"

    def match(self, manifest, ctx):
        return True

    def rewrite(self, manifest, ctx):
        return []


# No built-in rewriters — distributions/extensions populate this
_REWRITERS: list[IngressRewriter] = []


def _is_rewriter_class(obj, mod_name):
    """Check if obj is an ingress rewriter class defined in the given module."""
    return (isinstance(obj, type)
            and hasattr(obj, 'name') and isinstance(getattr(obj, 'name', None), str)
            and hasattr(obj, 'match') and callable(obj.match)
            and hasattr(obj, 'rewrite') and callable(obj.rewrite)
            and not hasattr(obj, 'kinds')
            and obj.__module__ == mod_name)


class IngressProvider(Provider):
    """Abstract ingress provider — rewriter dispatch + service/config generation.

    Subclasses implement build_service() and write_config() to support
    different reverse proxy backends (Caddy, Traefik, etc.).
    """
    name = "ingress"
    kinds = ["Ingress"]
    priority = 900

    def convert(self, _kind: str, manifests: list[dict], ctx: ConvertContext) -> ProviderResult:
        """Convert all Ingress manifests via rewriter dispatch.

        Like every extension, a rewriter sees its own `extensions: {<name>: …}`
        block as ctx.extension_config and is skipped when `enabled: false`.
        """
        own_config = ctx.extension_config
        extensions_config = ctx.config.get("extensions") or {}
        rewriters = []
        for rw in _REWRITERS:
            rw_conf = extensions_config.get(rw.name) or {}
            if not rw_conf.get("enabled", True):
                print(f"Rewriter disabled: {rw.name}", file=sys.stderr)
                continue
            rewriters.append((rw, rw_conf))
        entries = []
        for m in manifests:
            rewriter = self._find_rewriter(m, ctx, rewriters)
            entries.extend(rewriter.rewrite(m, ctx))
        ctx.extension_config = own_config  # back to the provider's own, for build_service
        services = {}
        if entries and not ctx.config.get("disable_ingress"):
            services = self.build_service(entries, ctx)
        return ProviderResult(services=services, ingress_entries=entries)

    def build_service(self, entries, ctx):
        """Build the reverse proxy compose service dict. Override in subclasses."""
        return {}

    def write_config(self, entries, output_dir, config):
        """Write the reverse proxy config file. Override in subclasses."""

    @staticmethod
    def _find_rewriter(manifest, ctx, rewriters):
        """Find the first matching rewriter for an Ingress manifest.

        *rewriters* is a list of (rewriter, its extension config); the
        matching rewriter's config is left in ctx.extension_config.
        """
        for rw, rw_conf in rewriters:
            ctx.extension_config = rw_conf
            if rw.match(manifest, ctx):
                return rw
        name = (manifest.get("metadata") or {}).get("name", "?")
        ctx.warnings.append(f"Ingress '{name}': no matching rewriter, skipped")
        return _NullRewriter()
