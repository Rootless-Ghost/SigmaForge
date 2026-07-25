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
from app import _convert_backend_safe

BACKENDS = ["splunk", "elastic", "eql", "sentinel", "wazuh", "qradar", "dac_json"]

# Templates whose condition is an aggregation ("selection | count(...) by field > N").
# Wazuh's backend does not support aggregation conditions and raises NotImplementedError.
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
    expect_not_implemented = backend == "wazuh" and key in AGGREGATION_TEMPLATES

    if expect_not_implemented:
        with pytest.raises(NotImplementedError):
            SIEMConverter.convert(rule_yaml, backend)
        return

    result = SIEMConverter.convert(rule_yaml, backend)
    assert isinstance(result, str)
    assert result.strip() != ""


def test_convert_backend_safe_preserves_notimplementederror_text():
    """NotImplementedError is raised deliberately by SIEMConverter (e.g. the
    Wazuh backend's lack of aggregation-condition support) with a message
    written for the end user, so _convert_backend_safe() must surface it
    verbatim rather than genericizing it."""
    rule_yaml = _RULE_YAML["brute_force_by_username"]
    result = _convert_backend_safe(
        rule_yaml, "wazuh", rule_id=100001, group_name="sigma_rules"
    )
    assert result.startswith("Conversion error:")
    assert "aggregation conditions" in result
    assert "TargetUserName" in result  # condition text from the real NotImplementedError message


def test_convert_backend_safe_genericizes_other_exceptions(caplog):
    """Any exception other than NotImplementedError (here: malformed YAML
    raising a yaml.YAMLError deep in SIEMConverter.convert()) must not leak
    its message, parser detail, or exception class name to the client — only
    the fixed generic message, with full detail logged server-side
    (CodeQL py/stack-trace-exposure)."""
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


def test_validator_surfaces_yaml_parse_error_text():
    """Intentional behavior, not a bug: CodeQL py/stack-trace-exposure alert #24
    on app.py's /api/validate route was dismissed because that endpoint exists
    specifically so a user can paste arbitrary Sigma YAML and be told why it
    fails to parse. SigmaValidator.validate() deliberately includes the
    yaml.YAMLError text in its errors list for exactly this reason — lock it
    in so a future "fix" for the CodeQL alert doesn't quietly break it."""
    malformed_yaml = "title: Broken Rule\ndetection: [unclosed\n"
    result = SigmaValidator.validate(malformed_yaml)

    assert result["valid"] is False
    assert any("YAML parse error" in err for err in result["errors"])
