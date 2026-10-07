import ast

from ast_sentinel.rules.exception_handling import ExceptionHandlingVisitor
from ast_sentinel.schemas.findings import Severity


def _analyze(source: str):
    visitor = ExceptionHandlingVisitor()
    tree = ast.parse(source)
    return visitor.analyze(tree, source.splitlines(), "test.py")


class TestBareExcept:
    def test_detects_bare_except(self):
        source = "try:\n    x = 1\nexcept:\n    print('err')"
        findings = _analyze(source)
        bare = [f for f in findings if "Bare" in f.message]
        assert len(bare) == 1
        assert bare[0].severity == Severity.MEDIUM

    def test_bare_except_with_pass(self):
        """Bare except + pass should produce TWO findings (bare + empty body)."""
        source = "try:\n    x = 1\nexcept:\n    pass"
        findings = _analyze(source)
        assert len(findings) == 2
        messages = {f.message for f in findings}
        assert any("Bare" in m for m in messages)
        assert any("Empty" in m for m in messages)


class TestBroadException:
    def test_detects_except_exception(self):
        source = "try:\n    x = 1\nexcept Exception:\n    print(e)"
        findings = _analyze(source)
        broad = [f for f in findings if "Broad" in f.message]
        assert len(broad) == 1
        assert broad[0].severity == Severity.LOW

    def test_except_exception_with_pass(self):
        """Broad except + pass should produce TWO findings."""
        source = "try:\n    x = 1\nexcept Exception as e:\n    pass"
        findings = _analyze(source)
        assert len(findings) == 2


class TestEmptyExceptBody:
    def test_detects_pass_only(self):
        source = "try:\n    x = 1\nexcept ValueError:\n    pass"
        findings = _analyze(source)
        empty = [f for f in findings if "Empty" in f.message]
        assert len(empty) == 1
        assert empty[0].severity == Severity.MEDIUM

    def test_ignores_body_with_logging(self):
        source = "try:\n    x = 1\nexcept ValueError:\n    print('error')"
        findings = _analyze(source)
        empty = [f for f in findings if "Empty" in f.message]
        assert len(empty) == 0


class TestSafePatterns:
    def test_specific_except_with_handling(self):
        source = "try:\n    x = 1\nexcept ValueError as e:\n    print(e)"
        findings = _analyze(source)
        assert len(findings) == 0

    def test_multiple_specific_excepts(self):
        source = """
try:
    x = int("abc")
except ValueError as e:
    print(e)
except TypeError as e:
    print(e)
"""
        findings = _analyze(source)
        assert len(findings) == 0

    def test_except_with_raise(self):
        source = "try:\n    x = 1\nexcept ValueError:\n    raise"
        findings = _analyze(source)
        # Not an empty body (has raise), and not bare/broad
        assert len(findings) == 0
