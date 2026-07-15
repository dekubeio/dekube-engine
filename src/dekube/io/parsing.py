"""Manifest parsing — helmfile template, YAML loading, namespace inference."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


def _helmfile_list_namespaces(helmfile_path: str,
                              environment: str | None = None) -> dict[str, str]:
    """Run ``helmfile list`` and return a release-name → namespace mapping."""
    cmd = ["helmfile", "--file", helmfile_path]
    if environment:
        cmd.extend(["--environment", environment])
    cmd.extend(["list", "--output", "json"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        releases = json.loads(result.stdout)
        return {r["name"]: r.get("namespace", "") for r in releases if r.get("namespace")}
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as exc:
        print(f"⚠ helmfile list failed ({exc.__class__.__name__}), "
              f"namespace inference will rely on manifest metadata only",
              file=sys.stderr)
        return {}


def run_helmfile_template(helmfile_dir: str, output_dir: str,
                          environment: str | None = None) -> tuple[str, dict[str, str]]:
    """Run helmfile template and return (rendered_dir, release_ns_map)."""
    rendered_dir = os.path.join(output_dir, ".helmfile-rendered")
    if os.path.exists(rendered_dir):
        shutil.rmtree(rendered_dir)
    os.makedirs(rendered_dir)
    # helmfile auto-detects .gotmpl extension
    helmfile_path = os.path.join(helmfile_dir, "helmfile.yaml")
    if not os.path.exists(helmfile_path):
        gotmpl = helmfile_path + ".gotmpl"
        if os.path.exists(gotmpl):
            helmfile_path = gotmpl
    cmd = ["helmfile", "--file", helmfile_path]
    if environment:
        cmd.extend(["--environment", environment])
    cmd.extend(["template", "--output-dir", rendered_dir])
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("Error: 'helmfile' not found in PATH — install helmfile or use --from-dir "
              "with pre-rendered manifests", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"Error: helmfile template failed (exit {exc.returncode}) — see output above",
              file=sys.stderr)
        sys.exit(1)
    # Nested helmfiles: helmfile creates per-child .helmfile-rendered dirs
    # instead of putting everything in the --output-dir target. Consolidate.
    helmfile_root = Path(helmfile_dir).resolve()
    main_rendered = Path(rendered_dir).resolve()
    for nested in sorted(helmfile_root.rglob(".helmfile-rendered")):
        if nested.resolve() == main_rendered:
            continue
        for yaml_file in nested.rglob("*.yaml"):
            rel = yaml_file.relative_to(nested)
            dest = main_rendered / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(yaml_file, dest)
        shutil.rmtree(nested)
    release_ns_map = _helmfile_list_namespaces(helmfile_path, environment)
    return rendered_dir, release_ns_map


def parse_manifests(rendered_dir: str) -> dict[str, list[dict]]:
    """Load all YAML files from rendered_dir, classify by kind.

    Each manifest gets an internal ``_release_dir`` annotation (the
    first path component relative to *rendered_dir*) so that downstream
    steps can group manifests by helmfile release.
    """
    manifests: dict[str, list[dict]] = {}
    rendered = Path(rendered_dir)
    for yaml_file in sorted(rendered.rglob("*.yaml")):
        # First path component relative to rendered_dir = release directory
        rel = yaml_file.relative_to(rendered)
        release_dir = rel.parts[0] if rel.parts else ""
        try:
            with open(yaml_file, encoding="utf-8") as f:
                for doc in yaml.safe_load_all(f):
                    if not doc or not isinstance(doc, dict):
                        continue
                    doc["_release_dir"] = release_dir
                    kind = doc.get("kind", "Unknown")
                    manifests.setdefault(kind, []).append(doc)
        except yaml.YAMLError as exc:
            print(f"⚠ Skipping {yaml_file.name}: {exc.__class__.__name__}",
                  file=sys.stderr)
    return manifests


def _extract_release_name(release_dir: str) -> str:
    """Extract the release name from a helmfile output directory name.

    Directory format: ``<helmfile-filename>-<hash>-<release-name>`` or just
    ``<name>``. The helmfile filename may be ``helmfile.yaml``/``helmfile.yml``
    and carry a ``.gotmpl`` suffix (both are supported by run_helmfile_template).
    """
    # e.g. "helmfile.yaml-01df6c56-minio" or
    #      "helmfile.yaml.gotmpl-01df6c56-minio" → "minio"
    for prefix in ("helmfile.yaml.gotmpl-", "helmfile.yml.gotmpl-",
                   "helmfile.yaml-", "helmfile.yml-"):
        if release_dir.startswith(prefix):
            rest = release_dir[len(prefix):]
            # Skip the hash part (first segment before '-')
            idx = rest.find("-")
            return rest[idx + 1:] if idx >= 0 else rest
    return release_dir


def _collect_known_namespaces(manifests: dict[str, list[dict]]) -> set[str]:
    """Collect all namespaces seen in manifests (declared + referenced)."""
    known = {(m.get("metadata") or {}).get("name", "")
             for m in manifests.get("Namespace", [])} - {""}
    for kind_list in manifests.values():
        for m in kind_list:
            ns = (m.get("metadata") or {}).get("namespace", "")
            if ns:
                known.add(ns)
    return known


def _build_dir_ns_map(manifests: dict[str, list[dict]],
                      release_ns_map: dict[str, str] | None = None) -> dict[str, str]:
    """Build a mapping of release directory → namespace.

    Strategy (each phase fills gaps left by the previous):
    1. Sibling inference — any manifest in the same release dir that has a namespace
    2. Namespace/release matching — match release name against known namespaces
    3. ``helmfile list`` data — from *release_ns_map* (only when using ``--helmfile-dir``)
    """
    all_release_dirs: set[str] = set()
    dir_ns: dict[str, str] = {}
    for kind_list in manifests.values():
        for m in kind_list:
            rd = m.get("_release_dir", "")
            if rd:
                all_release_dirs.add(rd)
                ns = (m.get("metadata") or {}).get("namespace", "")
                if ns and rd not in dir_ns:
                    dir_ns[rd] = ns

    known_ns = _collect_known_namespaces(manifests)
    for rd in all_release_dirs - dir_ns.keys():
        release_name = _extract_release_name(rd)
        if release_name in known_ns:
            dir_ns[rd] = release_name
        elif release_ns_map and release_name in release_ns_map:
            dir_ns[rd] = release_ns_map[release_name]
    return dir_ns


def _infer_namespaces(manifests: dict[str, list[dict]],
                      release_ns_map: dict[str, str] | None = None) -> None:
    """Fill missing ``metadata.namespace`` from sibling manifests or *release_ns_map*."""
    dir_ns = _build_dir_ns_map(manifests, release_ns_map)
    for kind_list in manifests.values():
        for m in kind_list:
            if not (m.get("metadata") or {}).get("namespace", ""):
                rd = m.get("_release_dir", "")
                if rd in dir_ns:
                    if not m.get("metadata"):
                        m["metadata"] = {}
                    m["metadata"]["namespace"] = dir_ns[rd]
