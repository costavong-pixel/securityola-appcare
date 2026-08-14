"""Validate that the hashed development lock matches its dependency inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)$")
_LOCK_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)(?:\s+\\)?$")
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})$")
_INPUT_MARKER = re.compile(r"^# appcare-lock-input-sha256: ([0-9a-f]{64})$")


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _parse_pin(value: str, source: str) -> tuple[str, str]:
    match = _PIN.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"{source} must contain exact name==version pins: {value!r}")
    return match.group(1), match.group(2)


def _read_requirements(path: Path) -> list[tuple[str, str]]:
    requirements: list[tuple[str, str]] = []
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").replace("\r\n", "\n").splitlines(), 1
    ):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        requirements.append(_parse_pin(line, f"{path.name}:{line_number}"))
    if not requirements:
        raise ValueError(f"{path.name} contains no dependency pins")
    return requirements


def _read_build_requirements(path: Path) -> list[tuple[str, str]]:
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    build_system = document.get("build-system")
    if not isinstance(build_system, dict) or not isinstance(build_system.get("requires"), list):
        raise ValueError("pyproject.toml must declare build-system.requires")
    requires = build_system["requires"]
    if not all(isinstance(value, str) for value in requires):
        raise ValueError("pyproject.toml build-system.requires must contain strings")
    return [_parse_pin(value, "pyproject.toml build-system.requires") for value in requires]


def input_manifest(repo_root: Path) -> dict[str, list[tuple[str, str]]]:
    return {
        "build-system.requires": _read_build_requirements(repo_root / "pyproject.toml"),
        "requirements-dev.txt": _read_requirements(repo_root / "requirements-dev.txt"),
    }


def input_digest(repo_root: Path) -> str:
    manifest = input_manifest(repo_root)
    encoded = json.dumps(
        {key: [[name, version] for name, version in value] for key, value in manifest.items()},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_lock(path: Path) -> tuple[str, dict[str, tuple[str, set[str]]]]:
    marker: str | None = None
    records: dict[str, tuple[str, set[str]]] = {}
    current_name: str | None = None
    current_version: str | None = None
    current_hashes: set[str] = set()

    def finish_record() -> None:
        nonlocal current_name, current_version, current_hashes
        if current_name is None or current_version is None:
            return
        normalized = _normalize_name(current_name)
        if normalized in records:
            raise ValueError(f"lock contains duplicate package: {current_name}")
        if not current_hashes:
            raise ValueError(f"lock entry has no sha256 hash: {current_name}=={current_version}")
        records[normalized] = (current_version, current_hashes)
        current_name = None
        current_version = None
        current_hashes = set()

    lines = path.read_text(encoding="utf-8").replace("\r\n", "\n").splitlines()
    for line_number, line in enumerate(lines, 1):
        marker_match = _INPUT_MARKER.fullmatch(line.strip())
        if marker_match is not None:
            if marker is not None:
                raise ValueError("lock contains duplicate input digest markers")
            marker = marker_match.group(1)
            continue
        pin_match = _LOCK_PIN.fullmatch(line.strip())
        if pin_match is not None:
            finish_record()
            current_name, current_version = pin_match.groups()
            continue
        hash_match = _HASH.fullmatch(line.strip())
        if hash_match is not None:
            if current_name is None:
                raise ValueError(f"lock hash appears before a package at line {line_number}")
            current_hashes.add(hash_match.group(1))
    finish_record()
    if marker is None:
        raise ValueError("lock is missing the appcare input digest marker")
    if not records:
        raise ValueError("lock contains no package entries")
    return marker, records


def validate(repo_root: Path) -> list[str]:
    repo_root = repo_root.resolve()
    try:
        manifest = input_manifest(repo_root)
        expected_digest = input_digest(repo_root)
        actual_digest, locked = _read_lock(repo_root / "requirements-dev.lock")
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        return [str(exc)]

    errors: list[str] = []
    if actual_digest != expected_digest:
        errors.append(
            "requirements-dev.lock input digest is stale "
            f"(expected {expected_digest}, found {actual_digest})"
        )

    direct_requirements = manifest["requirements-dev.txt"]
    required = manifest["build-system.requires"] + direct_requirements
    for name, version in required:
        normalized = _normalize_name(name)
        record = locked.get(normalized)
        if record is None:
            errors.append(f"lock is missing {name}=={version}")
            continue
        locked_version, hashes = record
        if locked_version != version:
            errors.append(
                f"lock version drift for {name}: expected {version}, found {locked_version}"
            )
        if not hashes:
            errors.append(f"lock entry has no sha256 hash: {name}=={locked_version}")

    if errors:
        return errors
    return [
        "build lock is fresh: "
        f"{len(direct_requirements)} development pins, "
        f"{len(locked)} hashed lock entries, input {expected_digest}"
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        result = validate(args.repo_root)
    except OSError as exc:
        print(f"build lock check failed: {exc}", file=sys.stderr)
        return 1
    if result and result[0].startswith("build lock is fresh:"):
        print(result[0])
        return 0
    print("build lock check failed:", file=sys.stderr)
    print("\n".join(f"- {error}" for error in result), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
