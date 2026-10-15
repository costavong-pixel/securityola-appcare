from __future__ import annotations

from appcare.backups.filesystem import _SecretContentScanner


def _scan_in_chunks(content: bytes, chunk_size: int = 257) -> bool:
    scanner = _SecretContentScanner()
    return any(
        scanner.feed(content[offset : offset + chunk_size])
        for offset in range(0, len(content), chunk_size)
    )


def test_define_secret_name_is_detected_past_fixed_overlap() -> None:
    content = b"<?php define(" + b" " * 5000 + b"'DB_PASSWORD', 'fixture-value');"

    assert _scan_in_chunks(content)


def test_define_secret_identifier_split_across_chunk_boundary() -> None:
    content = b"<?php define('DB_PASS" + b"WORD', 'fixture-value');"

    assert _scan_in_chunks(content, chunk_size=7)


def test_define_secret_name_with_comments_before_open_paren() -> None:
    block_comment = b"<?php define /*" + b"comment" * 40 + b"*/ ('DB_PASSWORD', 'fixture-value');"
    adjacent_comment = b"<?php define/* comment */('DB_PASSWORD', 'fixture-value');"
    line_comment = b"<?php define // comment\n ('DB_PASSWORD', 'fixture-value');"
    hash_comment = b"<?php define # comment\n ('DB_PASSWORD', 'fixture-value');"

    assert _scan_in_chunks(block_comment, chunk_size=11)
    assert _scan_in_chunks(adjacent_comment, chunk_size=5)
    assert _scan_in_chunks(line_comment, chunk_size=9)
    assert _scan_in_chunks(hash_comment, chunk_size=9)


def test_non_secret_define_is_not_classified_by_define_scanner() -> None:
    content = b"<?php define('APP_ROOT', '/srv/app');"

    assert not _scan_in_chunks(content)
