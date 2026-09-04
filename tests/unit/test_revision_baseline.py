"""P03 immutable baseline and source-mirror security coverage."""

from __future__ import annotations

import os
import socket
import stat
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from appcare.revision import (
    BaselineCaptureError,
    BaselineEntry,
    BaselinePolicy,
    CapturedApplicationRevision,
    EvidenceClass,
    FilesystemBaseline,
    FilesystemBaselineCapturer,
    ImmutableSourceMirror,
    LiveCaptureAuthorization,
    MirrorCaptureError,
    RevisionError,
    detect_source_type,
    read_git_revision,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="P03 baseline capture is Linux/POSIX-only"
)

CAPTURED_AT = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "approved-site"
    (root / "public").mkdir(parents=True)
    (root / "public" / "index.php").write_text("<?php echo 'safe';\n", encoding="utf-8")
    (root / "public" / "readme.txt").write_text("bounded source\n", encoding="utf-8")
    (root / "assets.bin").write_bytes(b"not mirrored binary")
    (root / ".env").write_text("API_KEY=must-not-be-read\n", encoding="utf-8")
    return root


def _revision(root: Path, *, policy: BaselinePolicy | None = None) -> CapturedApplicationRevision:
    capturer = FilesystemBaselineCapturer(policy)
    baseline = capturer.capture(root)
    return CapturedApplicationRevision.from_filesystem_baseline(
        baseline,
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
        host_identity="slab-prompt-ola",
        captured_at=CAPTURED_AT,
        runtime_metadata={"php": "8.3", "web_server": "nginx"},
        database_metadata={"engine": "mariadb"},
    )


def test_unchanged_capture_has_deterministic_manifest_and_baseline_digest(tmp_path: Path) -> None:
    root = _root(tmp_path)
    first = _revision(root)
    second = _revision(root)

    assert first.manifest_digest == second.manifest_digest
    assert first.baseline_digest == second.baseline_digest
    assert first.baseline_id == second.baseline_id
    assert first.evidence_digest == second.evidence_digest

    (root / "public" / "readme.txt").write_text("changed\n", encoding="utf-8")
    changed = _revision(root)
    assert changed.manifest_digest != first.manifest_digest
    assert changed.baseline_digest != first.baseline_digest


def test_secret_paths_are_metadata_only_and_never_hashed(tmp_path: Path) -> None:
    revision = _revision(_root(tmp_path))
    secret = next(entry for entry in revision.manifest if entry.relative_path == ".env")

    assert secret.classification == "excluded-secret"
    assert secret.sha256 is None
    assert "must-not-be-read" not in str(revision.as_dict())


def test_unverified_git_marker_is_treated_as_brownfield_filesystem(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (root / ".git" / "refs").mkdir()
    (root / ".git" / "refs" / "heads").mkdir()
    git_revision = "a" * 40
    (root / ".git" / "refs" / "heads" / "main").write_text(git_revision + "\n", encoding="ascii")

    assert detect_source_type(root) == "direct-filesystem"
    assert read_git_revision(root) is None
    captured = FilesystemBaselineCapturer().capture_revision(
        root,
        tenant_id="tenant-a",
        application_id="application-a",
        target_reference="target-a",
        host_identity="slab-prompt-ola",
        captured_at=CAPTURED_AT,
    )
    assert captured.source_type == "direct-filesystem"
    assert captured.source_revision is None
    assert captured.snapshot_semantics == "observed-tree-merkle-race-checked"


def test_mirror_capability_cannot_be_forged_without_sealed_receipt_attestation(
    tmp_path: Path,
) -> None:
    revision = _revision(_root(tmp_path))

    with pytest.raises(RevisionError, match="verified sealed receipt"):
        revision.with_mirror(
            receipt=object(),  # type: ignore[arg-type]
        )


def test_fixture_evidence_cannot_promote_real_target() -> None:
    entry = BaselineEntry(".", "directory", 0, 0o700, 0, 0)
    assert entry.classification == "included"


def test_fixture_revision_cannot_promote_real_target(tmp_path: Path) -> None:
    revision = _revision(_root(tmp_path))
    assert revision.evidence_class is EvidenceClass.FIXTURE
    assert revision.promotes_real_target is False

    evidence = revision.capability_evidence(stack_id="generic-linux")
    assert evidence.status.value == "unsupported"
    assert evidence.evidence_class is EvidenceClass.FIXTURE
    assert evidence.source_revision == revision.baseline_digest


def test_real_target_label_requires_live_transport_authorization(tmp_path: Path) -> None:
    root = _root(tmp_path)
    baseline = FilesystemBaselineCapturer().capture(root)

    with pytest.raises(BaselineCaptureError, match="live capture authorization"):
        CapturedApplicationRevision.from_filesystem_baseline(
            baseline,
            tenant_id="tenant-a",
            application_id="application-a",
            target_reference="target-a",
            host_identity="slab-prompt-ola",
            captured_at=CAPTURED_AT,
            evidence_class=EvidenceClass.REAL_TARGET,
        )

    with pytest.raises(BaselineCaptureError, match="live transport"):
        LiveCaptureAuthorization.from_inventory(
            object(),
            approved_root=baseline.root,
        )


def test_live_authorization_is_factory_only() -> None:
    with pytest.raises(TypeError, match="from_inventory"):
        LiveCaptureAuthorization()


def test_sealed_revision_exposes_scoped_source_capability_evidence(tmp_path: Path) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    outcome = ImmutableSourceMirror.for_test(tmp_path / "mirror").capture(revision, root)

    evidence = outcome.revision.capability_evidence(stack_id="generic-linux")
    assert evidence.status.value == "supported"
    assert evidence.tenant_id == revision.tenant_id
    assert evidence.application_id == revision.application_id
    assert evidence.source_revision == revision.baseline_digest
    assert evidence.artifact_digest == outcome.receipt.mirror_digest


def test_mirror_copies_only_source_like_files_and_seals_immutably(tmp_path: Path) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    mirror = ImmutableSourceMirror.for_test(tmp_path / "mirror")

    outcome = mirror.capture(revision, root)
    final = Path(outcome.receipt.mirror_path)

    assert outcome.receipt.sealed
    assert outcome.receipt.file_count == 2
    assert (final / "public" / "index.php").read_text(encoding="utf-8") == "<?php echo 'safe';\n"
    assert (final / "public" / "readme.txt").exists()
    assert not (final / "assets.bin").exists()
    assert not (final / ".env").exists()
    assert mirror.verify(outcome.receipt)
    if os.name == "posix":
        assert stat.S_IMODE(final.stat().st_mode) == 0o500
        assert stat.S_IMODE((final / "public" / "index.php").stat().st_mode) == 0o400

    with pytest.raises(MirrorCaptureError, match="replay|overwrite"):
        mirror.capture(revision, root)


def test_mirror_verify_rejects_content_or_permission_tampering(tmp_path: Path) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    mirror = ImmutableSourceMirror.for_test(tmp_path / "mirror")
    outcome = mirror.capture(revision, root)
    final = Path(outcome.receipt.mirror_path)
    copied = final / "public" / "index.php"

    os.chmod(copied, 0o600)
    if os.name == "posix":
        assert not mirror.verify(outcome.receipt)
    copied.write_text("tampered\n", encoding="utf-8")
    os.chmod(copied, 0o400)
    assert not mirror.verify(outcome.receipt)


def test_mirror_verify_rejects_unexpected_directory_tampering(tmp_path: Path) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    mirror = ImmutableSourceMirror.for_test(tmp_path / "mirror")
    outcome = mirror.capture(revision, root)
    final = Path(outcome.receipt.mirror_path)
    public = final / "public"

    os.chmod(public, 0o700)
    (public / "unexpected").mkdir()
    os.chmod(public, 0o500)
    os.chmod(public / "unexpected", 0o500)

    assert not mirror.verify(outcome.receipt)


def test_mirror_rejects_reserved_metadata_name_in_source(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "public" / "manifest.json").write_text("{}\n", encoding="utf-8")
    revision = _revision(root)

    with pytest.raises(MirrorCaptureError, match="metadata"):
        ImmutableSourceMirror.for_test(tmp_path / "mirror").capture(revision, root)


def test_mirror_serializes_same_scope_and_rejects_replay(tmp_path: Path) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    first_mirror = ImmutableSourceMirror.for_test(tmp_path / "mirror")
    second_mirror = ImmutableSourceMirror.for_test(tmp_path / "mirror")

    first = first_mirror.capture(revision, root)
    assert first_mirror.verify(first.receipt)
    with pytest.raises(MirrorCaptureError, match="replay|overwrite"):
        second_mirror.capture(revision, root)


def test_mirror_rejects_cross_scope_and_manifest_mismatch(tmp_path: Path) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    mirror = ImmutableSourceMirror.for_test(tmp_path / "mirror")

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(MirrorCaptureError, match="manifest|match"):
        mirror.capture(
            CapturedApplicationRevision.from_filesystem_baseline(
                FilesystemBaselineCapturer().capture(root),
                tenant_id="tenant-a",
                application_id="application-a",
                target_reference="target-b",
                host_identity="slab-prompt-ola",
                captured_at=CAPTURED_AT,
                baseline_id="fixed-baseline",
            ),
            outside,
        )

    with pytest.raises(RevisionError):
        CapturedApplicationRevision.from_filesystem_baseline(
            FilesystemBaselineCapturer().capture(root),
            tenant_id="tenant/escape",
            application_id="application-a",
            target_reference="target-a",
            host_identity="slab-prompt-ola",
            captured_at=CAPTURED_AT,
        )

    (root / "public" / "index.php").write_text("changed\n", encoding="utf-8")
    with pytest.raises((MirrorCaptureError, BaselineCaptureError)):
        mirror.capture(revision, root)


def test_secret_bearing_source_content_is_not_copied(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "public" / "embedded.php").write_text(
        "<?php $api_key='suspicious';\n", encoding="utf-8"
    )
    (root / "public" / "helpers.php").write_text(
        "<?php $password = 'suspicious';\n", encoding="utf-8"
    )
    (root / "public" / "settings.yaml").write_text("client_secret: suspicious\n", encoding="utf-8")
    (root / "public" / "environment.ini").write_text(
        "DATABASE_URL=mysql://suspicious\n", encoding="utf-8"
    )
    (root / "public" / "constants.php").write_text(
        "<?php define('DB_PASSWORD', 'suspicious');\n", encoding="utf-8"
    )
    (root / "public" / "config-map.php").write_text(
        "<?php return ['DB_PASSWORD' => 'suspicious'];\n", encoding="utf-8"
    )
    revision = _revision(root)
    outcome = ImmutableSourceMirror.for_test(tmp_path / "mirror").capture(revision, root)

    assert not (Path(outcome.receipt.mirror_path) / "public" / "embedded.php").exists()
    final = Path(outcome.receipt.mirror_path)
    assert not (final / "public" / "helpers.php").exists()
    assert not (final / "public" / "settings.yaml").exists()
    assert not (final / "public" / "environment.ini").exists()
    assert not (final / "public" / "constants.php").exists()
    assert not (final / "public" / "config-map.php").exists()
    assert outcome.receipt.excluded_file_count >= 7


def test_symlink_escape_is_rejected_without_following_it(tmp_path: Path) -> None:
    root = _root(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (root / "escape").symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(BaselineCaptureError, match="symlink"):
        FilesystemBaselineCapturer().capture(root)


def test_safe_symlink_is_recorded_without_following_it(tmp_path: Path) -> None:
    root = _root(tmp_path)
    try:
        (root / "index-link").symlink_to("public/index.php")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    revision = _revision(root)
    link = next(entry for entry in revision.manifest if entry.relative_path == "index-link")
    assert link.entry_type == "symlink"
    assert link.classification == "excluded-symlink"
    assert link.symlink_target == "public/index.php"


@pytest.mark.skipif(os.name != "posix", reason="POSIX special files are required")
def test_special_files_and_hard_links_fail_closed(tmp_path: Path) -> None:
    root = _root(tmp_path)
    os.link(root / "public" / "index.php", root / "hard-link.php")
    with pytest.raises(BaselineCaptureError, match="hard-linked"):
        FilesystemBaselineCapturer().capture(root)

    (root / "hard-link.php").unlink()
    fifo = root / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(BaselineCaptureError, match="special"):
        FilesystemBaselineCapturer().capture(root)


@pytest.mark.skipif(os.name != "posix", reason="POSIX sockets are required")
def test_socket_is_rejected(tmp_path: Path) -> None:
    root = _root(tmp_path)
    path = root / "socket"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        with pytest.raises(BaselineCaptureError, match="special"):
            FilesystemBaselineCapturer().capture(root)
    finally:
        server.close()
        path.unlink(missing_ok=True)


def test_resource_limits_reject_oversized_file_and_entry_bomb(tmp_path: Path) -> None:
    root = _root(tmp_path)
    with pytest.raises(BaselineCaptureError, match="exceeds capture limit"):
        FilesystemBaselineCapturer(BaselinePolicy(max_file_bytes=2, max_total_bytes=100)).capture(
            root
        )

    root = tmp_path / "many"
    root.mkdir()
    for index in range(4):
        (root / f"file-{index}.txt").write_text("x", encoding="ascii")
    with pytest.raises(BaselineCaptureError, match="too many"):
        FilesystemBaselineCapturer(
            BaselinePolicy(max_entries=3, max_file_bytes=10, max_total_bytes=100)
        ).capture(root)


def test_toctou_source_replacement_is_detected_and_staging_is_cleaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    original_capture = FilesystemBaselineCapturer.capture
    calls = 0

    def changing_capture(capturer: FilesystemBaselineCapturer, current: Path) -> FilesystemBaseline:
        nonlocal calls
        baseline = original_capture(capturer, current)
        calls += 1
        if calls == 1:
            replacement = current / "public" / "index.php"
            replacement.unlink()
            replacement.write_text("replacement\n", encoding="utf-8")
        return baseline

    monkeypatch.setattr(FilesystemBaselineCapturer, "capture", changing_capture)

    mirror_root = tmp_path / "mirror"
    with pytest.raises((MirrorCaptureError, BaselineCaptureError), match="changed|match|metadata"):
        ImmutableSourceMirror.for_test(mirror_root).capture(
            revision,
            root,
        )
    assert not tuple(mirror_root.rglob("*.staging-*"))


def test_mirror_rejects_source_root_identity_replacement_after_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    original_capture = FilesystemBaselineCapturer.capture
    calls = 0

    def replacing_capture(
        capturer: FilesystemBaselineCapturer, current: Path
    ) -> FilesystemBaseline:
        nonlocal calls
        baseline = original_capture(capturer, current)
        calls += 1
        if calls == 2:
            assert baseline.root_identity is not None
            return replace(
                baseline,
                root_identity=(baseline.root_identity[0], baseline.root_identity[1] + 1),
            )
        return baseline

    monkeypatch.setattr(FilesystemBaselineCapturer, "capture", replacing_capture)

    mirror_root = tmp_path / "mirror"
    with pytest.raises(MirrorCaptureError, match="identity|contents"):
        ImmutableSourceMirror.for_test(mirror_root).capture(revision, root)
    assert not (
        mirror_root / "tenant-a" / "application-a" / "target-a" / revision.baseline_id
    ).exists()
    assert not tuple(mirror_root.rglob("*.staging-*"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX mirror ancestry permissions are required")
def test_mirror_rejects_untrusted_writable_ancestry(tmp_path: Path) -> None:
    unsafe_parent = tmp_path / "unsafe-parent"
    unsafe_parent.mkdir()
    original_mode = stat.S_IMODE(unsafe_parent.stat().st_mode)
    unsafe_mode = original_mode | stat.S_IWOTH
    os.chmod(unsafe_parent, unsafe_mode)
    try:
        with pytest.raises(MirrorCaptureError, match="ancestry"):
            ImmutableSourceMirror.for_test(unsafe_parent / "mirror")
    finally:
        os.chmod(unsafe_parent, original_mode)


def test_no_network_or_secret_receipt_content_is_persisted(tmp_path: Path) -> None:
    root = _root(tmp_path)
    revision = _revision(root)
    outcome = ImmutableSourceMirror.for_test(tmp_path / "mirror").capture(revision, root)
    receipt_text = (Path(outcome.receipt.mirror_path) / "receipt.json").read_text(encoding="utf-8")

    assert "must-not-be-read" not in receipt_text
    assert "API_KEY" not in receipt_text
    assert "http://" not in receipt_text
    assert "https://" not in receipt_text
