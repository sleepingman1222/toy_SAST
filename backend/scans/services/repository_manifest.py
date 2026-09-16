import fnmatch
import hashlib
import json
import os
import shutil
from pathlib import Path, PurePosixPath

from django.utils import timezone

from ..constants import (
    IGNORED_LANGUAGE_DIRECTORIES,
    LANGUAGE_EXTENSIONS,
    MAX_ANALYZABLE_FILE_BYTES,
)
from .source_snapshot import (
    ANALYSIS_WORKSPACE_MANIFEST_NAME,
    get_analysis_workspace_run_root,
    get_analysis_workspace_source_root,
)


MANIFEST_SCHEMA_VERSION = 2
PROJECT_MARKER_PATTERNS = (
    "pyproject.toml",
    "requirements*.txt",
    "package.json",
    "pom.xml",
    "build.gradle*",
)


class RepositoryManifestError(RuntimeError):
    pass


def _sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_marker(name):
    return any(fnmatch.fnmatch(name, pattern) for pattern in PROJECT_MARKER_PATTERNS)


def _normalized_ignore_lines(path):
    return [
        line.strip()
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _contained_relative_path(root, path):
    root = Path(root).resolve(strict=True)
    path = Path(path).resolve(strict=True)
    try:
        return path.relative_to(root).as_posix()
    except ValueError as error:
        raise RepositoryManifestError("manifest path escapes repository root") from error


def _copy_evidence_file(source_root, workspace_root, relative_path):
    source = Path(source_root) / PurePosixPath(relative_path)
    destination = Path(workspace_root) / PurePosixPath(relative_path)
    if destination.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o600)


def build_repository_manifest(analysis_run_id, original_root, snapshot_files):
    original_root = Path(original_root).resolve(strict=True)
    workspace_root = get_analysis_workspace_source_root(analysis_run_id)
    if not workspace_root.is_dir():
        raise RepositoryManifestError("immutable workspace source root is missing")

    snapshot_by_path = {item.relative_path: item for item in snapshot_files}
    inventory = []

    for current_root, directory_names, file_names in os.walk(original_root, followlinks=False):
        current_path = Path(current_root)
        relative_directory = current_path.relative_to(original_root)
        ignored_parent = any(
            part.lower() in IGNORED_LANGUAGE_DIRECTORIES
            for part in relative_directory.parts
        )
        directory_names[:] = sorted(
            name for name in directory_names
            if not (current_path / name).is_symlink()
        )

        for file_name in sorted(file_names):
            source = current_path / file_name
            if source.is_symlink() or not source.is_file():
                continue
            relative_path = _contained_relative_path(original_root, source)
            suffix = source.suffix.lower()
            language = LANGUAGE_EXTENSIONS.get(suffix, "")
            kind = None
            extra = {}
            if language:
                kind = "supported_source"
                size = source.stat().st_size
                if ignored_parent:
                    eligible = False
                    exclusion_reason = "ignored_by_policy"
                elif size > MAX_ANALYZABLE_FILE_BYTES:
                    eligible = False
                    exclusion_reason = "oversized"
                else:
                    eligible = relative_path in snapshot_by_path
                    exclusion_reason = "" if eligible else "ignored_by_policy"
                extra = {
                    "language": language,
                    "eligibility": eligible,
                    "exclusion_reason": exclusion_reason,
                }
            elif file_name == ".semgrepignore":
                kind = "semgrep_ignore"
                extra = {"normalized_lines": _normalized_ignore_lines(source)}
            elif _is_marker(file_name):
                kind = "project_marker"

            if kind is None:
                continue

            inventory.append({
                "path": relative_path,
                "kind": kind,
                "size": source.stat().st_size,
                "content_sha256": _sha256_file(source),
                **extra,
            })
            if kind != "supported_source":
                _copy_evidence_file(original_root, workspace_root, relative_path)

    inventory.sort(key=lambda item: (item["path"], item["kind"]))
    canonical = {"schema_version": MANIFEST_SCHEMA_VERSION, "inventory": inventory}
    canonical_bytes = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    snapshot_digest = hashlib.sha256(canonical_bytes).hexdigest()

    manifest = {
        **canonical,
        "analysis_run_id": int(analysis_run_id),
        "created_at": timezone.now().isoformat(),
        "snapshot_digest": snapshot_digest,
        # Retained for the v1 snapshot reader during the compatibility window.
        "files": [
            {
                "relative_path": item.relative_path,
                "language": item.language,
                "size_bytes": item.size_bytes,
                "file_class": item.file_class,
                "content_sha256": item.content_sha256,
            }
            for item in snapshot_files
        ],
    }
    manifest_path = get_analysis_workspace_run_root(analysis_run_id) / ANALYSIS_WORKSPACE_MANIFEST_NAME
    temporary_path = manifest_path.with_suffix(".v2.tmp")
    with temporary_path.open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary_path.chmod(0o600)
    os.replace(temporary_path, manifest_path)
    return manifest


def load_repository_manifest(analysis_run_id):
    path = get_analysis_workspace_run_root(analysis_run_id) / ANALYSIS_WORKSPACE_MANIFEST_NAME
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise RepositoryManifestError("unsupported repository manifest schema")
    canonical = {"schema_version": MANIFEST_SCHEMA_VERSION, "inventory": data.get("inventory", [])}
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    if digest != data.get("snapshot_digest"):
        raise RepositoryManifestError("repository manifest digest mismatch")
    return data
