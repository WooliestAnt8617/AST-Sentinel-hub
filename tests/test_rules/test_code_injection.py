import ast

from ast_sentinel.rules.code_injection import CodeInjectionVisitor
from ast_sentinel.schemas.findings import Severity


def _analyze(source: str):
    visitor = CodeInjectionVisitor()
    tree = ast.parse(source)
    return visitor.analyze(tree, source.splitlines(), "test.py")


class TestEvalExec:
    def test_detects_eval_with_variable(self):
        findings = _analyze("result = eval(user_input)")
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-002"
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_eval_with_literal(self):
        findings = _analyze('result = eval("1 + 2")')
        assert len(findings) == 0

    def test_detects_exec_with_variable(self):
        findings = _analyze("exec(code_string)")
        assert len(findings) == 1

    def test_detects_compile(self):
        findings = _analyze("compile(user_code, '<string>', 'exec')")
        assert len(findings) == 1

    def test_detects_eval_in_fstring(self):
        findings = _analyze('eval(f"func({x})")')
        assert len(findings) == 1


class TestSubprocess:
    def test_detects_shell_true(self):
        source = 'import subprocess\nsubprocess.call("ls", shell=True)'
        findings = _analyze(source)
        shell_findings = [f for f in findings if "shell" in f.message.lower()]
        assert len(shell_findings) == 1
        assert shell_findings[0].severity == Severity.HIGH

    def test_ignores_shell_false(self):
        source = 'import subprocess\nsubprocess.run(["ls", "-la"], shell=False)'
        findings = _analyze(source)
        shell_findings = [f for f in findings if "shell" in f.message.lower()]
        assert len(shell_findings) == 0

    def test_ignores_no_shell_kwarg(self):
        source = 'import subprocess\nsubprocess.run(["ls", "-la"])'
        findings = _analyze(source)
        shell_findings = [f for f in findings if "shell" in f.message.lower()]
        assert len(shell_findings) == 0

    def test_detects_subprocess_popen_shell(self):
        source = 'import subprocess\nsubprocess.Popen(cmd, shell=True)'
        findings = _analyze(source)
        shell_findings = [f for f in findings if "shell" in f.message.lower()]
        assert len(shell_findings) == 1


class TestRemediation:
    def test_eval_remediation_suggests_literal_eval(self):
        findings = _analyze("eval(data)")
        assert "literal_eval" in findings[0].remediation

    def test_shell_remediation_suggests_list(self):
        source = 'import subprocess\nsubprocess.call("ls", shell=True)'
        findings = _analyze(source)
        shell_f = [f for f in findings if "shell" in f.message.lower()]
        assert "list" in shell_f[0].remediation.lower()
