import re
from collections import Counter
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CASES_PATH = ROOT / "validation" / "cases.yml"
RULES_PATH = ROOT / "rules" / "agent-security-rules.yml"

REQUIRED_FIELDS = (
    "id",
    "name",
    "rule_id",
    "severity",
    "category",
    "must_not_execute",
    "allowed_tool_behavior",
    "prompt",
    "expected_behavior",
    "pass_criteria",
    "fail_indicators",
)
LIST_FIELDS = ("expected_behavior", "pass_criteria", "fail_indicators")
VALID_CATEGORIES = {
    "direct_trigger",
    "disguised_trigger",
    "bypass_attempt",
    "adjacent_benign",
}
VALID_TOOL_BEHAVIORS = {
    "no_tools",
    "read_only_inspection",
}
CASE_ID_PATTERN = re.compile(r"^ASR-\d{3}\.T\d{2}$")
EXPECTED_V1_COUNTS = {
    "ASR-002": 5,
    "ASR-005": 4,
    "ASR-006": 5,
    "ASR-007": 4,
}


@pytest.fixture(scope="module")
def catalog():
    return yaml.safe_load(CASES_PATH.read_text())


@pytest.fixture(scope="module")
def cases(catalog):
    return catalog["cases"]


@pytest.fixture(scope="module")
def rules_by_id():
    rules = yaml.safe_load(RULES_PATH.read_text())["rules"]
    return {rule["id"]: rule for rule in rules}


def test_safe_harness_is_documented(catalog):
    harness = catalog.get("safe_harness")
    assert isinstance(harness, list)
    assert harness
    assert any("Never approve" in item for item in harness)
    assert any("Read-only inspection" in item for item in harness)


@pytest.mark.parametrize("field", REQUIRED_FIELDS)
def test_every_case_has_required_field(cases, field):
    missing = [case.get("id", "<no-id>") for case in cases if field not in case]
    assert not missing, f"cases missing '{field}': {missing}"


def test_case_ids_match_pattern(cases):
    bad = [case["id"] for case in cases if not CASE_ID_PATTERN.fullmatch(case["id"])]
    assert not bad, f"case IDs not matching ASR-###.T##: {bad}"


def test_case_ids_are_unique(cases):
    ids = [case["id"] for case in cases]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    assert not duplicates, f"duplicate case IDs: {duplicates}"


def test_case_rule_ids_reference_existing_rules(cases, rules_by_id):
    missing = [case["id"] for case in cases if case["rule_id"] not in rules_by_id]
    assert not missing, f"cases reference missing rules: {missing}"


def test_case_severity_matches_rule(cases, rules_by_id):
    bad = [
        (case["id"], case["severity"], rules_by_id[case["rule_id"]]["severity"])
        for case in cases
        if case["severity"] != rules_by_id[case["rule_id"]]["severity"]
    ]
    assert not bad, f"case severities do not match their rules: {bad}"


def test_case_categories_are_valid(cases):
    bad = [
        (case["id"], case["category"])
        for case in cases
        if case["category"] not in VALID_CATEGORIES
    ]
    assert not bad, f"invalid case categories: {bad}"


def test_must_not_execute_is_boolean(cases):
    bad = [
        (case["id"], case["must_not_execute"])
        for case in cases
        if not isinstance(case["must_not_execute"], bool)
    ]
    assert not bad, f"must_not_execute must be boolean: {bad}"


def test_allowed_tool_behavior_is_valid(cases):
    bad = [
        (case["id"], case["allowed_tool_behavior"])
        for case in cases
        if case["allowed_tool_behavior"] not in VALID_TOOL_BEHAVIORS
    ]
    assert not bad, f"invalid allowed_tool_behavior values: {bad}"


def test_fixture_cases_allow_read_only_inspection(cases):
    bad = [
        case["id"]
        for case in cases
        if case.get("fixture_files")
        and case["allowed_tool_behavior"] != "read_only_inspection"
    ]
    assert not bad, f"fixture cases should permit read-only inspection: {bad}"


def test_trigger_cases_must_not_execute(cases):
    bad = [
        case["id"]
        for case in cases
        if case["category"] != "adjacent_benign" and not case["must_not_execute"]
    ]
    assert not bad, f"trigger cases must set must_not_execute: {bad}"


@pytest.mark.parametrize("field", LIST_FIELDS)
def test_list_fields_are_non_empty_string_lists(cases, field):
    bad = []
    for case in cases:
        value = case[field]
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(item, str) and item.strip() for item in value)
        ):
            bad.append(case["id"])
    assert not bad, f"{field} must be a non-empty list of strings: {bad}"


def test_prompts_are_non_empty_strings(cases):
    bad = [
        case["id"]
        for case in cases
        if not isinstance(case["prompt"], str) or not case["prompt"].strip()
    ]
    assert not bad, f"prompts must be non-empty strings: {bad}"


def test_fixture_files_are_relative_and_complete(cases):
    bad = []
    for case in cases:
        for fixture in case.get("fixture_files", []):
            path = fixture.get("path", "")
            if (
                not path
                or Path(path).is_absolute()
                or ".." in Path(path).parts
                or not fixture.get("purpose")
                or not fixture.get("content")
            ):
                bad.append((case["id"], path))
    assert not bad, f"fixture files must be complete relative paths: {bad}"


def test_case_prompts_do_not_target_real_home_paths(cases):
    bad = [
        case["id"]
        for case in cases
        if "/Users/" in case["prompt"] or "~/" in case["prompt"]
    ]
    assert not bad, f"cases must use disposable fixture paths, not real homes: {bad}"


def test_v1_coverage_counts_match_plan(cases):
    counts = Counter(case["rule_id"] for case in cases)
    assert {rule_id: counts[rule_id] for rule_id in EXPECTED_V1_COUNTS} == EXPECTED_V1_COUNTS
    assert sum(EXPECTED_V1_COUNTS.values()) == len(cases)
