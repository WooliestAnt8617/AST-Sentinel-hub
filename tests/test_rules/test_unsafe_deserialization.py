import ast

from ast_sentinel.rules.unsafe_deserialization import UnsafeDeserializationVisitor
from ast_sentinel.schemas.findings import Severity


def _analyze(source: str):
    visitor = UnsafeDeserializationVisitor()
    tree = ast.parse(source)
    return visitor.analyze(tree, source.splitlines(), "test.py")


class TestPickle:
    def test_detects_pickle_loads(self):
        findings = _analyze("import pickle\npickle.loads(data)")
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-005"
        assert findings[0].severity == Severity.HIGH

    def test_detects_pickle_load(self):
        findings = _analyze("import pickle\npickle.load(open('f', 'rb'))")
        assert len(findings) == 1


class TestMarshal:
    def test_detects_marshal_loads(self):
        findings = _analyze("import marshal\nmarshal.loads(data)")
        assert len(findings) == 1

    def test_detects_marshal_load(self):
        findings = _analyze("import marshal\nmarshal.load(f)")
        assert len(findings) == 1


class TestShelve:
    def test_detects_shelve_open(self):
        findings = _analyze("import shelve\nshelve.open('mydb')")
        assert len(findings) == 1


class TestYAML:
    def test_detects_yaml_load_without_safe_loader(self):
        findings = _analyze("import yaml\nyaml.load(data)")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_ignores_yaml_safe_load(self):
        findings = _analyze("import yaml\nyaml.safe_load(data)")
        assert len(findings) == 0

    def test_ignores_yaml_load_with_safe_loader_kwarg(self):
        findings = _analyze("import yaml\nyaml.load(data, Loader=yaml.SafeLoader)")
        assert len(findings) == 0

    def test_ignores_yaml_load_with_safe_loader_name(self):
        findings = _analyze("import yaml\nyaml.load(data, Loader=SafeLoader)")
        assert len(findings) == 0


class TestRemediation:
    def test_pickle_remediation_suggests_json(self):
        findings = _analyze("import pickle\npickle.loads(data)")
        assert "json" in findings[0].remediation.lower()

    def test_yaml_remediation_suggests_safe_load(self):
        findings = _analyze("import yaml\nyaml.load(data)")
        assert "safe_load" in findings[0].remediation.lower()
