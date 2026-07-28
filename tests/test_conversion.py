"""
Conversion regression tests for SIEMConverter / SigmaValidator.

Covers the full RULE_TEMPLATES x backend matrix, plus targeted regressions
for the aggregation-condition fix (windows_logon_brute_force,
firewall_port_scan, brute_force_by_username on Splunk/Sentinel).
"""
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.sigma_engine import (
    RULE_TEMPLATES,
    SIEMConverter,
    SigmaValidator,
    build_rule_from_template,
)
from app import _convert_backend_safe, _wazuh_unsupported_message

BACKENDS = ["splunk", "elastic", "eql", "sentinel", "wazuh", "qradar", "dac_json"]

# Templates whose condition is an aggregation ("selection | count(...) by field > N").
# Wazuh's backend does not support aggregation conditions and returns a
# structured {"supported": False, "reason": "aggregation_condition"} result
# instead of raising (CodeQL py/stack-trace-exposure: response text must
# never be derived from a caught exception object).
AGGREGATION_TEMPLATES = {
    "windows_logon_brute_force",
    "firewall_port_scan",
    "brute_force_by_username",
}

TEMPLATE_KEYS = list(RULE_TEMPLATES.keys())

# Build each template's YAML once and reuse across all parametrized cases.
_RULE_YAML = {key: build_rule_from_template(key).to_yaml() for key in TEMPLATE_KEYS}


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("key", TEMPLATE_KEYS)
def test_convert_matrix(key, backend):
    rule_yaml = _RULE_YAML[key]
    expect_unsupported = backend == "wazuh" and key in AGGREGATION_TEMPLATES

    result = SIEMConverter.convert(rule_yaml, backend)

    if expect_unsupported:
        assert isinstance(result, dict)
        assert result.get("supported") is False
        assert result.get("reason") == "aggregation_condition"
        return

    assert not isinstance(result, dict), (
        f"{key!r}/{backend!r} unexpectedly returned a structured "
        f"unsupported result: {result!r}"
    )
    assert isinstance(result, str)
    assert result.strip() != ""


def test_convert_backend_safe_uses_static_message_for_unsupported_wazuh_condition():
    """Known Wazuh syntax gaps (e.g. aggregation conditions) are signaled by
    SIEMConverter as a structured {"supported": False, "reason": ...} result,
    never an exception, and _convert_backend_safe() must render the
    corresponding STATIC message from _WAZUH_UNSUPPORTED_MESSAGES — not any
    text derived from the rule content or a caught exception object
    (CodeQL py/stack-trace-exposure)."""
    rule_yaml = _RULE_YAML["brute_force_by_username"]
    result = _convert_backend_safe(
        rule_yaml, "wazuh", rule_id=100001, group_name="sigma_rules"
    )
    assert result == f"Conversion error: {_wazuh_unsupported_message('aggregation_condition')}"
    assert "aggregation conditions" in result
    assert "TargetUserName" not in result  # no rule-derived content in the message


def test_convert_backend_safe_genericizes_other_exceptions(caplog):
    """Any actual exception (here: malformed YAML raising a yaml.YAMLError
    deep in SIEMConverter.convert()) — as opposed to the structured
    {"supported": False, ...} result used for known Wazuh syntax gaps — must
    not leak its message, parser detail, or exception class name to the
    client. Only the fixed generic message reaches the response, with full
    detail logged server-side (CodeQL py/stack-trace-exposure)."""
    with caplog.at_level(logging.ERROR):
        result = _convert_backend_safe("not: [valid yaml structure", "splunk")

    assert result == "Conversion error: An internal error occurred while converting to this backend."
    assert "Traceback" not in result
    assert "yaml" not in result.lower()
    assert "YAMLError" not in result
    assert "line" not in result and "column" not in result  # yaml.scanner detail markers

    # Full detail must still reach the server-side log.
    assert any(
        "Unexpected error converting rule to backend" in record.message
        for record in caplog.records
    )


@pytest.mark.parametrize("key", TEMPLATE_KEYS)
def test_template_validates(key):
    validation = SigmaValidator.validate(_RULE_YAML[key])
    assert validation["valid"] is True, validation["errors"]


@pytest.mark.parametrize("key", sorted(AGGREGATION_TEMPLATES))
def test_splunk_aggregation_has_no_search_keyword(key):
    """Regression: _build_aggregation() used to prefix the base query with a
    literal 'search ', producing invalid '| where search ...' SPL."""
    result = SIEMConverter.convert(_RULE_YAML[key], "splunk")
    assert "where search" not in result


@pytest.mark.parametrize("key", sorted(AGGREGATION_TEMPLATES))
def test_sentinel_aggregation_has_no_orphan_comment_or_duplicate_where(key):
    """Regression: _build_aggregation() used to emit an unlabeled
    '// Base filter' comment and a '| where' stage that convert() then
    duplicated with its own '| where' wrapper."""
    result = SIEMConverter.convert(_RULE_YAML[key], "sentinel")
    assert "// Base filter" not in result

    lines = [line.strip() for line in result.splitlines()]
    for prev_line, curr_line in zip(lines, lines[1:]):
        assert not (prev_line.startswith("| where") and curr_line.startswith("| where")), (
            f"duplicated adjacent '| where' clauses in sentinel output "
            f"for {key!r}:\n{result}"
        )


def test_validator_yaml_parse_error_is_static_not_exception_derived():
    """CodeQL py/stack-trace-exposure alerts #23/#25/#26 flagged the SUCCESS
    return path in app.py because SigmaValidator.validate()'s result (which
    is always included in those responses) embedded str(e) from the caught
    yaml.YAMLError. The previous "alert #24 dismissed" design (surfacing the
    raw yaml.YAMLError text) is superseded: the validator must now build its
    own static parse-failure message and never reach into the exception
    object, so no yaml library/module/parser detail can reach an HTTP
    response."""
    malformed_yaml = "title: Broken Rule\ndetection: [unclosed\n"
    result = SigmaValidator.validate(malformed_yaml)

    assert result["valid"] is False
    assert any("YAML parse error" in err for err in result["errors"])
    joined_errors = " ".join(result["errors"])
    assert "yaml." not in joined_errors.lower()
    assert "line " not in joined_errors.lower()
    assert "column" not in joined_errors.lower()
