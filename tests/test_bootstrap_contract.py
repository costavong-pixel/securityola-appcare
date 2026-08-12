from pathlib import Path

from scripts.check_public_safety import scan
from scripts.verify_worker_policy import verify

ROOT = Path(__file__).resolve().parents[1]


def test_appcare_repository_contract_is_present() -> None:
    assert (ROOT / "AGENTS.md").is_file()
    assert (ROOT / ".specify" / "memory" / "constitution.md").is_file()
    assert (ROOT / ".agents" / "skills" / "speckit-constitution" / "SKILL.md").is_file()
    assert (ROOT / "graphify-out" / "graph.json").is_file() or not (ROOT / "graphify-out").exists()


def test_public_safety_contract_is_clean() -> None:
    assert scan(ROOT) == []


def test_worker_policy_is_bounded() -> None:
    assert verify(ROOT) == []
