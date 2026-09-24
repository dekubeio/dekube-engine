"""Constants, regexes, and kind lists used throughout the converter."""

import re

# Workload name patterns auto-excluded on first run (K8s-only infra)
AUTO_EXCLUDE_PATTERNS = ("cert-manager", "ingress", "reflector")

# K8s internal DNS → compose service name
# CBA: a leading pod label (StatefulSet ordinal) is absorbed and discarded, so
# pod-0.svc and pod-1.svc both collapse to svc — compose runs one replica, so
# the ordinal has nowhere to go. Upgrade path: map ordinals to distinct compose
# services when replica support exists.
_K8S_DNS_RE = re.compile(
    r'(?<![a-z0-9._-])'                            # left boundary: don't start mid-hostname
    r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)?'      # pod label, e.g. StatefulSet ordinal (discarded)
    r'([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.'       # service name (captured)
    r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.'       # namespace (discarded)
    r'svc(?:\.cluster\.local)?'                    # svc[.cluster.local]
    r'(?![a-z0-9-]|\.[a-z0-9])'                    # must end the hostname
)

# Placeholder for referencing secrets in overrides/custom services: $secret:<name>:<key>
# The key stops at the first char a K8s Secret key can't hold ([-._a-zA-Z0-9]),
# so "$secret:db:password@db:5432" doesn't swallow the "@db" of a URL.
_SECRET_REF_RE = re.compile(r'\$secret:([^:]+):([-._a-zA-Z0-9]+)')

# K8s kinds we warn about (not convertible to compose)
UNSUPPORTED_KINDS = (
    "CronJob", "HorizontalPodAutoscaler", "PodDisruptionBudget",
)

# K8s kinds silently ignored (no compose equivalent, no useful warning)
IGNORED_KINDS = (
    "Certificate", "ClusterIssuer", "Issuer",
    "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding",
    "CustomResourceDefinition", "IngressClass", "Namespace",
    "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
    "NetworkPolicy", "ServiceAccount",
)

# K8s kinds that produce compose services (iterated together everywhere)
WORKLOAD_KINDS = ("DaemonSet", "Deployment", "Job", "Pod", "StatefulSet")

# K8s $(VAR) interpolation in command/args (kubelet resolves these from env vars).
# Mirrors k8s third_party/forked/golang/expansion: "$$" is an escape for "$"
# (so "$$(VAR)" is a literal "$(VAR)"), "$(...)" runs to the first ")".
_K8S_VAR_REF_RE = re.compile(r'\$(?:\$|\(([^)]*)\))')

# Regex boundary for URL port rewriting (matches end-of-string or path/whitespace/quote)
_URL_BOUNDARY = r'''(?=[/\s"']|$)'''
