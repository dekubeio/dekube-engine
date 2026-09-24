"""Volume mount conversion — PVC, ConfigMap, Secret, emptyDir."""

import base64
import hashlib
import json
import os

from dekube.pacts.helpers import apply_replacements, is_excluded, _secret_bytes
from dekube.core.env import _apply_port_remap


def _build_vol_map(pod_volumes: list,
                    volume_claim_templates: list | None = None,
                    sts_name: str | None = None) -> dict:
    """Build a map of volume name → volume source from pod spec volumes.

    For StatefulSets, volumeClaimTemplates define implicit PVC volumes
    mounted by the template metadata.name; their claim is <vct>-<sts>
    (bare <vct> kept as legacy_claim for pre-existing dekube.yaml mappings).
    """
    vol_map = {}
    for vct in (volume_claim_templates or []):
        if not vct:
            continue
        vname = (vct.get("metadata") or {}).get("name", "")
        if not vname:
            continue
        if sts_name:
            # K8s names it <vct>-<sts>-<ordinal>; compose runs one replica → <vct>-<sts>
            vol_map[vname] = {"type": "pvc", "claim": f"{vname}-{sts_name}",
                              "legacy_claim": vname}
        else:
            vol_map[vname] = {"type": "pvc", "claim": vname}
    for v in pod_volumes:
        if not v:  # null list item (Helm conditional inside volumes)
            continue
        vname = v.get("name", "")
        if "persistentVolumeClaim" in v:
            pvc = v["persistentVolumeClaim"] or {}
            vol_map[vname] = {"type": "pvc", "claim": pvc.get("claimName", "")}
        elif "configMap" in v:
            cm = v["configMap"] or {}
            vol_map[vname] = {"type": "configmap", "name": cm.get("name", ""),
                              "items": cm.get("items"), "default_mode": cm.get("defaultMode")}
        elif "secret" in v:
            sec = v["secret"] or {}
            vol_map[vname] = {"type": "secret", "name": sec.get("secretName", ""),
                              "items": sec.get("items"), "default_mode": sec.get("defaultMode")}
        elif "emptyDir" in v:
            vol_map[vname] = {"type": "emptydir"}
        else:
            vol_map[vname] = {"type": "unknown"}
    return vol_map


def _resolve_host_path(host_path: str, volume_root: str) -> str:
    """Resolve host_path: bare names are prefixed with volume_root, explicit paths kept as-is."""
    if host_path.startswith(("/", "./", "../")):
        return host_path
    return f"{volume_root}/{host_path}"


def _convert_pvc_mount(claim: str, mount_path: str, pvc_names: set,
                       config: dict, warnings: list[str],
                       legacy_claim: str | None = None) -> str:
    """Convert a PVC volume mount to a compose volume string."""
    volumes_cfg = config.get("volumes") or {}
    if legacy_claim and claim not in volumes_cfg and legacy_claim in volumes_cfg:
        # dekube.yaml from before <vct>-<sts> naming: keep the user's data path.
        # Warned once per claim by _warn_legacy_vct_mappings.
        claim = legacy_claim
    pvc_names.add(claim)
    vol_cfg = volumes_cfg.get(claim)
    if vol_cfg and isinstance(vol_cfg, dict) and "host_path" in vol_cfg:
        resolved = _resolve_host_path(vol_cfg["host_path"], config.get("volume_root", "./data"))
        return f"{resolved}:{mount_path}"
    if vol_cfg is not None:
        return f"{claim}:{mount_path}"
    warnings.append(f"PVC '{claim}' has no mapping in dekube.yaml — add it manually")
    return f"{claim}:{mount_path}"


# K8s mode for configMap/secret volume files without defaultMode/items[].mode
# (ConfigMapVolumeSourceDefaultMode / SecretVolumeSourceDefaultMode)
_DEFAULT_FILE_MODE = 0o644


def _file_mode(mode, fallback: int) -> int:
    """A K8s ``mode``/``defaultMode`` value, or ``fallback`` when unset/invalid."""
    return mode if isinstance(mode, int) and not isinstance(mode, bool) else fallback


def _host_mode(mode: int) -> int:
    """Mode applied to a generated file on the host."""
    # CBA: read bits are forced on for group/other. The files are bind-mounted owned
    # by the host user (not root/fsGroup as in K8s), so an exact 0400/0600 would make
    # them unreadable to a container running as any other uid. Exec bits follow K8s.
    # Upgrade path: exact modes once something chowns these files to the container uid.
    return (mode & 0o777) | 0o444


def _resolve_data_keys(available_keys: list, items: list | None,
                       default_mode=None) -> list[tuple[str, str, int]]:
    """Return (source_key, output_filename, mode) triples for a ConfigMap/Secret volume.

    Without ``items``, every available key is written under its own name. With
    ``items``, only the listed keys are written (K8s key-filtering), each
    optionally renamed to its ``path``. ``items[].mode`` overrides ``defaultMode``
    (K8s default 0644).
    """
    base_mode = _file_mode(default_mode, _DEFAULT_FILE_MODE)
    if items:
        triples = []
        for item in items:
            if not item:
                continue
            key = item.get("key")
            if not key:
                continue
            triples.append((key, item.get("path") or key, _file_mode(item.get("mode"), base_mode)))
        return triples
    return [(k, k, base_mode) for k in available_keys]


def _data_dir_name(name: str, items: list | None, default_mode=None) -> str:
    """Directory name for a generated ConfigMap/Secret tree.

    Without ``items``: ``<name>`` (shared by every such mount). With ``items``:
    ``<name>_<hash>`` so mounts filtering different keys don't share one tree
    ('_' can't appear in a K8s name, so this never collides with a real one).
    """
    if not items:
        return name
    digest = hashlib.sha256(json.dumps([items, default_mode], sort_keys=True,
                                       default=str).encode()).hexdigest()
    return f"{name}_{digest[:8]}"


def _warn_mode_conflict(abs_dir: str, keys: list, label: str, warnings: list[str]) -> None:
    """Warn when a reused tree lacks exec bits this mount's modes ask for."""
    # CBA: the no-items tree is shared by every mount of the object (its path is kept
    # stable), so the first mount's modes win. Upgrade path: key it by defaultMode too.
    for _key, out_name, mode in keys:
        path = os.path.join(abs_dir, out_name)
        if os.path.isfile(path) and mode & 0o111 & ~os.stat(path).st_mode:
            warnings.append(f"{label} is mounted with different defaultMode values — "
                            f"'{out_name}' keeps the first mount's mode (not executable)")
            return


def _generate_configmap_files(cm_name: str, cm_data: dict, output_dir: str,
                              generated_cms: set, warnings: list[str],
                              replacements: list[dict] | None = None,
                              service_port_map: dict | None = None,
                              binary_data: dict | None = None,
                              items: list | None = None,
                              default_mode=None) -> str:
    """Write ConfigMap data/binaryData entries as files. Returns the directory path (relative).

    Honours volume ``items`` (key filtering + key→path rename) and file modes,
    matching Secret behaviour.
    """
    dir_name = _data_dir_name(cm_name, items, default_mode)
    rel_dir = os.path.join("configmaps", dir_name)
    abs_dir = os.path.join(output_dir, rel_dir)
    binary_data = binary_data or {}
    keys = _resolve_data_keys(list(cm_data) + list(binary_data), items, default_mode)
    if dir_name in generated_cms:
        _warn_mode_conflict(abs_dir, keys, f"ConfigMap '{cm_name}'", warnings)
    else:
        generated_cms.add(dir_name)
        os.makedirs(abs_dir, exist_ok=True)
        for key, out_name, mode in keys:
            file_path = os.path.join(abs_dir, out_name)
            if not os.path.realpath(file_path).startswith(os.path.realpath(output_dir) + os.sep):
                warnings.append(f"ConfigMap '{cm_name}' key '{out_name}' would escape output directory — skipped")
                continue
            if "/" in out_name:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
            if key in cm_data:
                rewritten = str(cm_data[key])
                if service_port_map:
                    rewritten = _apply_port_remap(rewritten, service_port_map)
                if replacements:
                    rewritten = apply_replacements(rewritten, replacements)
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(rewritten)
            elif key in binary_data:
                with open(file_path, "wb") as f:
                    f.write(base64.b64decode(binary_data[key]))
            else:
                warnings.append(f"ConfigMap '{cm_name}' item key '{key}' not found in data/binaryData — skipped")
                continue
            os.chmod(file_path, _host_mode(mode))
    return f"./{rel_dir}"


def _resolve_secret_keys(secret: dict, items: list | None,
                         default_mode=None) -> list[tuple[str, str, int]]:
    """Return (key, output_filename, mode) triples for a Secret volume mount."""
    available = list((secret.get("data") or {})) + list((secret.get("stringData") or {}))
    return _resolve_data_keys(list(dict.fromkeys(available)), items, default_mode)


def _generate_secret_files(sec_name: str, secret: dict, items: list | None,
                           output_dir: str, generated_secrets: set,
                           warnings: list[str],
                           replacements: list[dict] | None = None,
                           default_mode=None) -> str:
    """Write Secret data entries as files. Returns the directory path (relative).

    Files hold the decoded bytes, as kubelet mounts them; replacements only
    apply to values that are UTF-8 text.
    """
    dir_name = _data_dir_name(sec_name, items, default_mode)
    rel_dir = os.path.join("secrets", dir_name)
    abs_dir = os.path.join(output_dir, rel_dir)
    keys = _resolve_secret_keys(secret, items, default_mode)
    if dir_name in generated_secrets:
        _warn_mode_conflict(abs_dir, keys, f"Secret '{sec_name}'", warnings)
    else:
        generated_secrets.add(dir_name)
        os.makedirs(abs_dir, exist_ok=True)
        for key, out_name, mode in keys:
            raw = _secret_bytes(secret, key)
            if raw is None:
                warnings.append(f"Secret '{sec_name}' key '{key}' could not be decoded — skipped")
                continue
            try:
                val = raw.decode("utf-8")
            except UnicodeDecodeError:
                val = None  # binary (keystore, DER cert…): written as-is
            if val is not None and replacements:
                val = apply_replacements(val, replacements)
            out_path = os.path.join(abs_dir, out_name)
            if not os.path.realpath(out_path).startswith(os.path.realpath(output_dir) + os.sep):
                warnings.append(f"Secret '{sec_name}' key '{out_name}' would escape output directory — skipped")
                continue
            if "/" in out_name:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
            if val is None:
                with open(out_path, "wb") as f:
                    f.write(raw)
            else:
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(val)
            os.chmod(out_path, _host_mode(mode))
    return f"./{rel_dir}"


def _convert_data_mount(data_dir: str, vm: dict) -> str:
    """Build a bind-mount string for a configmap/secret directory, with optional subPath."""
    mount_path = vm.get("mountPath", "")
    sub_path = vm.get("subPath")
    if sub_path:
        return f"{data_dir}/{sub_path}:{mount_path}:ro"
    return f"{data_dir}:{mount_path}:ro"


def convert_volume_mounts(volume_mounts: list, pod_volumes: list, pvc_names: set,
                           config: dict, workload_name: str, warnings: list[str],
                           configmaps: dict | None = None, secrets: dict | None = None,
                           output_dir: str = ".", generated_cms: set | None = None,
                           generated_secrets: set | None = None,
                           replacements: list[dict] | None = None,
                           service_port_map: dict | None = None,
                           volume_claim_templates: list | None = None,
                           sts_name: str | None = None) -> list[str]:
    """Convert volumeMounts to docker-compose volume strings.

    Pass ``sts_name`` for StatefulSets so volumeClaimTemplate claims are named <vct>-<sts>.
    """
    vol_map = _build_vol_map(pod_volumes, volume_claim_templates, sts_name)
    result = []
    for vm in volume_mounts:
        if not vm:  # null list item (Helm conditional inside volumeMounts)
            continue
        source = vol_map.get(vm.get("name", ""), {})
        mount_path = vm.get("mountPath", "")
        vol_type = source.get("type")

        if vol_type == "pvc":
            result.append(_convert_pvc_mount(source["claim"], mount_path, pvc_names, config,
                                             warnings, legacy_claim=source.get("legacy_claim")))
        elif vol_type == "emptydir":
            result.append(mount_path)
        elif vol_type == "configmap" and configmaps is not None:
            cm = configmaps.get(source["name"])
            if cm is None:
                warnings.append(f"ConfigMap '{source['name']}' referenced by {workload_name} not found")
                continue
            cm_dir = _generate_configmap_files(source["name"], cm.get("data") or {},
                                               output_dir, generated_cms, warnings,
                                               replacements=replacements,
                                               service_port_map=service_port_map,
                                               binary_data=cm.get("binaryData") or {},
                                               items=source.get("items"),
                                               default_mode=source.get("default_mode"))
            result.append(_convert_data_mount(cm_dir, vm))
        elif vol_type == "secret" and secrets is not None:
            sec = secrets.get(source["name"])
            if sec is None:
                warnings.append(f"Secret '{source['name']}' referenced by {workload_name} not found")
                continue
            sec_dir = _generate_secret_files(source["name"], sec, source.get("items"),
                                             output_dir, generated_secrets, warnings,
                                             replacements=replacements,
                                             default_mode=source.get("default_mode"))
            result.append(_convert_data_mount(sec_dir, vm))

    return result


def _warn_legacy_vct_mappings(manifests: dict, config: dict, warnings: list[str]) -> None:
    """Warn about VCT PVCs still resolved through a bare-name dekube.yaml mapping."""
    volumes_cfg = config.get("volumes") or {}
    exclude = config.get("exclude") or []
    by_legacy: dict[str, list[str]] = {}
    for m in manifests.get("StatefulSet") or []:
        if not m:
            continue
        sts = (m.get("metadata") or {}).get("name", "")
        if not sts or is_excluded(sts, exclude):
            continue
        for vct in (m.get("spec") or {}).get("volumeClaimTemplates") or []:
            vname = ((vct or {}).get("metadata") or {}).get("name", "")
            claim = f"{vname}-{sts}"
            if vname and claim not in volumes_cfg and vname in volumes_cfg:
                by_legacy.setdefault(vname, []).append(claim)
    for vname, claims in sorted(by_legacy.items()):
        for claim in claims:
            warnings.append(f"PVC '{claim}': using legacy mapping '{vname}' — "
                            f"rename it to '{claim}' in dekube.yaml")
        if len(claims) > 1:
            warnings.append(f"PVC collision: {', '.join(claims)} share legacy mapping "
                            f"'{vname}' (same data directory) — give each its own "
                            f"entry and host_path in dekube.yaml")


# Backward compat alias (deprecated)
_convert_volume_mounts = convert_volume_mounts
