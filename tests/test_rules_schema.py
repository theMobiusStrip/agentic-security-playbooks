import re
from pathlib import Path

import pytest
import yaml

RULES_PATH = (
    Path(__file__).resolve().parent.parent / "rules" / "agent-security-rules.yml"
)
REQUIRED_FIELDS = ("id", "name", "severity", "trigger", "required_action")
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
ID_PATTERN = re.compile(r"^ASR-\d{3}$")


@pytest.fixture(scope="module")
def rules():
    data = yaml.safe_load(RULES_PATH.read_text())
    return data["rules"]


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
def test_every_rule_has_required_field(rules, field):
    missing = [r.get("id", "<no-id>") for r in rules if field not in r]
    assert not missing, f"rules missing '{field}': {missing}"


def test_rule_ids_match_pattern(rules):
    bad = [r["id"] for r in rules if not ID_PATTERN.fullmatch(str(r["id"]))]
    assert not bad, f"rule IDs not matching ^ASR-\\d{{3}}$: {bad}"


def test_rule_ids_are_unique(rules):
    ids = [r["id"] for r in rules]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"duplicate rule IDs: {duplicates}"


def test_severities_are_valid(rules):
    bad = [
        (r["id"], r["severity"])
        for r in rules
        if r["severity"] not in VALID_SEVERITIES
    ]
    assert not bad, f"invalid severities (must be one of {VALID_SEVERITIES}): {bad}"


def test_rule_names_are_unique(rules):
    names = [r["name"] for r in rules]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    assert not duplicates, f"duplicate rule names: {duplicates}"
