import ast

from ast_sentinel.rules.sql_injection import SQLInjectionVisitor
from ast_sentinel.schemas.findings import Severity


def _analyze(source: str):
    visitor = SQLInjectionVisitor()
    tree = ast.parse(source)
    return visitor.analyze(tree, source.splitlines(), "test.py")


class TestDirectDynamicQueries:
    def test_detects_fstring_in_execute(self):
        source = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
        findings = _analyze(source)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-003"
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_percent_formatting_in_execute(self):
        source = 'cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % name)'
        findings = _analyze(source)
        assert len(findings) == 1

    def test_detects_format_call_in_execute(self):
        source = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))'
        findings = _analyze(source)
        assert len(findings) == 1

    def test_detects_string_concat_in_execute(self):
        source = 'cursor.execute("SELECT * FROM users WHERE id = " + uid)'
        findings = _analyze(source)
        assert len(findings) == 1

    def test_ignores_parameterized_query(self):
        source = 'cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))'
        findings = _analyze(source)
        assert len(findings) == 0

    def test_ignores_static_string(self):
        source = 'cursor.execute("SELECT * FROM users")'
        findings = _analyze(source)
        assert len(findings) == 0


class TestIndirectDynamicQueries:
    """Tests for variable-tracking: query built on one line, executed on another."""

    def test_detects_variable_with_percent_format(self):
        source = '''
query = "SELECT * FROM users WHERE name = '%s'" % name
cursor.execute(query)
'''
        findings = _analyze(source)
        assert len(findings) == 1

    def test_detects_variable_with_fstring(self):
        source = '''
query = f"SELECT * FROM users WHERE id = {uid}"
cursor.execute(query)
'''
        findings = _analyze(source)
        assert len(findings) == 1

    def test_detects_variable_with_concat(self):
        source = '''
query = "SELECT * FROM users WHERE id = " + uid
cursor.execute(query)
'''
        findings = _analyze(source)
        assert len(findings) == 1

    def test_ignores_safe_variable(self):
        source = '''
query = "SELECT * FROM users"
cursor.execute(query)
'''
        findings = _analyze(source)
        assert len(findings) == 0


class TestExecuteMethods:
    def test_detects_executemany(self):
        source = 'cursor.executemany(f"INSERT INTO t VALUES ({v})", data)'
        findings = _analyze(source)
        assert len(findings) == 1

    def test_detects_executescript(self):
        source = 'cursor.executescript(f"DROP TABLE {name}")'
        findings = _analyze(source)
        assert len(findings) == 1
