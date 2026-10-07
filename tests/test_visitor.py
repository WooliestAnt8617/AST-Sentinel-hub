import ast

from ast_sentinel.core.visitor import (
    PythonASTNode,
    PythonAstRuleVisitor,
)
from ast_sentinel.schemas.findings import Severity


class TestPythonASTNode:
    def test_wraps_ast_node(self):
        tree = ast.parse("x = 1")
        assign = tree.body[0]
        node = PythonASTNode(assign)
        assert node.type == "Assign"
        assert node.start_point[0] == 1  # line 1
        assert node.start_point[1] == 0  # col 0

    def test_end_point(self):
        tree = ast.parse("x = 1")
        assign = tree.body[0]
        node = PythonASTNode(assign)
        end_line, end_col = node.end_point
        assert end_line >= 1


class TestPythonAstRuleVisitor:
    def test_analyze_returns_findings(self):
        class TestRule(PythonAstRuleVisitor):
            rule_id = "TEST-001"
            rule_name = "Test Rule"
            severity = Severity.LOW

            def visit_Assign(self, node):
                self.report(node, "Found assignment", "Don't assign things")
                self.generic_visit(node)

        source = "x = 1"
        tree = ast.parse(source)
        visitor = TestRule()
        findings = visitor.analyze(tree, source.splitlines(), "test.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "TEST-001"
        assert findings[0].location.file_path == "test.py"

    def test_code_snippet_extraction(self):
        class TestRule(PythonAstRuleVisitor):
            rule_id = "TEST-002"
            rule_name = "Snippet Test"
            severity = Severity.INFO

            def visit_Assign(self, node):
                self.report(node, "test", "test")
                self.generic_visit(node)

        source = "line1 = 1\nline2 = 2\nline3 = 3"
        tree = ast.parse(source)
        visitor = TestRule()
        findings = visitor.analyze(tree, source.splitlines(), "test.py")
        # First finding should have a code snippet containing actual source
        assert "line1" in findings[0].code_snippet

    def test_findings_reset_between_calls(self):
        class TestRule(PythonAstRuleVisitor):
            rule_id = "TEST-003"
            rule_name = "Reset Test"
            severity = Severity.LOW

            def visit_Assign(self, node):
                self.report(node, "found", "fix")
                self.generic_visit(node)

        visitor = TestRule()
        tree1 = ast.parse("x = 1")
        tree2 = ast.parse("y = 2")

        f1 = visitor.analyze(tree1, ["x = 1"], "a.py")
        assert len(f1) == 1

        f2 = visitor.analyze(tree2, ["y = 2"], "b.py")
        assert len(f2) == 1  # Not 2 — findings should reset

    def test_severity_override(self):
        class TestRule(PythonAstRuleVisitor):
            rule_id = "TEST-004"
            rule_name = "Override Test"
            severity = Severity.LOW

            def visit_Assign(self, node):
                self.report(node, "critical!", "fix", severity_override=Severity.CRITICAL)
                self.generic_visit(node)

        visitor = TestRule()
        findings = visitor.analyze(ast.parse("x = 1"), ["x = 1"], "t.py")
        assert findings[0].severity == Severity.CRITICAL
