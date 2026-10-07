from ast_sentinel.core.registry import get_registry
from ast_sentinel.schemas.findings import Severity


class TestRuleRegistry:
    def test_discovers_all_rules(self):
        registry = get_registry()
        rules = registry.get_all_rules()
        assert len(rules) >= 6
        expected_ids = {"SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006"}
        assert expected_ids.issubset(set(rules.keys()))

    def test_get_rule_by_id(self):
        registry = get_registry()
        rule = registry.get_rule("SEC-001")
        assert rule is not None
        assert rule.rule_id == "SEC-001"

    def test_get_nonexistent_rule(self):
        registry = get_registry()
        rule = registry.get_rule("SEC-999")
        assert rule is None

    def test_get_rules_by_severity_critical(self):
        registry = get_registry()
        rules = registry.get_rules_by_severity(Severity.CRITICAL)
        # Only rules with CRITICAL severity
        for rule_cls in rules.values():
            assert rule_cls.severity == Severity.CRITICAL

    def test_get_rules_by_severity_medium_includes_higher(self):
        registry = get_registry()
        rules = registry.get_rules_by_severity(Severity.MEDIUM)
        # Should include MEDIUM, HIGH, and CRITICAL
        severities = {cls.severity for cls in rules.values()}
        assert Severity.LOW not in severities
        assert Severity.INFO not in severities

    def test_singleton_pattern(self):
        r1 = get_registry()
        r2 = get_registry()
        assert r1 is r2

    def test_rules_have_required_attributes(self):
        registry = get_registry()
        for rule_id, rule_cls in registry.get_all_rules().items():
            assert hasattr(rule_cls, 'rule_id')
            assert hasattr(rule_cls, 'rule_name')
            assert hasattr(rule_cls, 'severity')
            assert isinstance(rule_cls.severity, Severity)
