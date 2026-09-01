from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest

from appcare.connectors import release_binding
from appcare.connectors.ssh_command_wrapper import (
    SshCommandProfile,
    SSHCommandRejected,
    profile_id,
    validate_original_command,
)


def _profile(tmp_path: Path) -> SshCommandProfile:
    if os.name == "posix":
        root_path = tmp_path / "app"
        root_path.mkdir()
        (root_path / "config.json").write_text("safe", encoding="utf-8")
        root = root_path.as_posix()
    else:
        root = "/srv/app"
    return SshCommandProfile(
        target_reference="target-a",
        approved_application_roots=(root,),
        approved_service_names=("app.service",),
        max_file_bytes=1024,
    )


def test_profile_id_is_non_secret_and_stable() -> None:
    assert profile_id("target-a") == profile_id("target-a")
    assert len(profile_id("target-a")) == 64


def test_profile_round_trips_without_secret_material(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    assert SshCommandProfile.from_dict(profile.to_dict()) == profile
    assert "secret" not in repr(profile).casefold()


def test_installed_wrapper_scrubs_python_import_environment() -> None:
    wrapper = Path(__file__).parents[2] / "ops" / "ssh" / "securityola-appcare-ssh-wrapper"
    text = wrapper.read_text(encoding="utf-8")
    source = Path(__file__).parents[2] / "appcare" / "connectors" / "ssh_command_wrapper.py"
    assert "/usr/bin/env -i" in text
    assert '"SSH_ORIGINAL_COMMAND=${SSH_ORIGINAL_COMMAND-}"' in text
    assert "/usr/bin/python3 -I -E -s -m appcare.connectors.ssh_command_wrapper" in text
    assert "verify_release_binding(module_path=Path(__file__))" in source.read_text(
        encoding="utf-8"
    )
    binding_source = (
        Path(__file__).parents[2] / "appcare" / "connectors" / "release_binding.py"
    ).read_text(encoding="utf-8")
    assert "ssh-release.json" in binding_source
    assert '"binding_sha256"' in binding_source
    assert "approved-release.json" in binding_source
    assert '"artifact_sha256"' in binding_source
    assert '"installed artifact is not approved"' in binding_source
    if os.name == "posix":
        assert stat.S_IMODE(wrapper.stat().st_mode) & 0o111
        subprocess.run(("/bin/sh", "-n", str(wrapper)), check=True)  # noqa: S603


def test_approved_release_record_is_strict_and_artifact_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    revision = "a" * 40
    artifact = "b" * 64
    monkeypatch.setattr(
        release_binding,
        "APPCARE_APPROVED_RELEASE_PATH",
        tmp_path / "approved-release.json",
    )
    monkeypatch.setattr(
        release_binding,
        "_read_trusted_file",
        lambda path, field_name: json.dumps(
            {
                "schema_version": 1,
                "release_revision": revision,
                "package_version": "0.0.0",
                "artifact_sha256": artifact,
            }
        ).encode("utf-8"),
    )
    assert release_binding._approved_release() == {
        "release_revision": revision,
        "package_version": "0.0.0",
        "artifact_sha256": artifact,
    }

    monkeypatch.setattr(
        release_binding,
        "_read_trusted_file",
        lambda path, field_name: json.dumps(
            {
                "schema_version": 1,
                "release_revision": revision,
                "package_version": "0.0.0",
                "artifact_sha256": artifact,
                "unexpected": "field",
            }
        ).encode("utf-8"),
    )
    with pytest.raises(release_binding.ReleaseBindingError):
        release_binding._approved_release()


def test_release_artifact_installs_wrapper_in_libexec() -> None:
    project = Path(__file__).parents[2]
    config = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["setuptools"]["data-files"]["libexec"] == [
        "ops/ssh/securityola-appcare-ssh-wrapper",
        "ops/ssh/install-securityola-appcare-release",
    ]
    assert config["project"]["scripts"]["securityola-appcare-install-release"] == (
        "appcare.connectors.release_binding:main"
    )
    installer = project / "ops" / "ssh" / "install-securityola-appcare-release"
    assert "/usr/bin/python3 -I -E -s -m appcare.connectors.release_binding" in installer.read_text(
        encoding="utf-8"
    )


def test_wrapper_accepts_only_typed_read_only_commands(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    root = profile.approved_application_roots[0]
    assert validate_original_command("hostname", profile) == ("hostname",)
    assert validate_original_command(f"stat --format=%F:%s -- {root}/config.json", profile)
    assert validate_original_command(f"stat --format=%n:%F:%U:%G:%a -- {root}", profile)
    assert validate_original_command(
        "systemctl show --no-pager "
        "--property=Id,LoadState,ActiveState,SubState,FragmentPath app.service",
        profile,
    )


def test_wrapper_accepts_every_registry_command_shape(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    root = profile.approved_application_roots[0]
    commands = (
        ("true",),
        ("hostname",),
        ("uname", "-srm"),
        ("cat", "--", "/etc/os-release"),
        ("ss", "-lntH"),
        ("nginx", "-V"),
        ("apache2", "-v"),
        ("httpd", "-v"),
        ("python3", "--version"),
        ("node", "--version"),
        ("php", "--version"),
        ("head", "-c", "1024", "--", f"{root}/config.json"),
        ("realpath", "-e", "--", root),
        ("realpath", "--", f"{root}/config.json"),
        ("df", "-P", "-k", "--", root),
        ("stat", "--format=%n:%F:%U:%G:%a:%s", "--", root),
        ("stat", "--format=%n:%F:%U:%G:%a", "--", root),
        ("stat", "--format=%F:%s", "--", f"{root}/config.json"),
        (
            "systemctl",
            "show",
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,FragmentPath",
            "app.service",
        ),
    )
    for command in commands:
        assert validate_original_command(shlex.join(command), profile) == command


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        'python3 -c \'open("/tmp/pwned", "w").write("x")\'',
        "cat /etc/shadow",
        "cat -- /tmp/outside",
        "head -c 10 -- /etc/passwd",
        "head -c ١٠ -- /srv/app/config.json",
        "hostname; id",
    ],
)
def test_wrapper_rejects_arbitrary_or_escaping_commands(tmp_path: Path, command: str) -> None:
    with pytest.raises(SSHCommandRejected):
        validate_original_command(command, _profile(tmp_path))
