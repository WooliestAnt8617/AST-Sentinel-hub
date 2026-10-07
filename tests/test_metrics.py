import ast

from ast_sentinel.metrics.complexity import ComplexityAnalyzer
from ast_sentinel.metrics.risk_score import compute_risk_score, risk_grade
from ast_sentinel.schemas.findings import (
    FileAnalysis,
    Finding,
    Location,
    ScanResult,
    ScanSummary,
    Severity,
)


class TestComplexityAnalyzer:
    def test_simple_function(self):
        tree = ast.parse("def foo():\n    return 1")
        analyzer = ComplexityAnalyzer()
        agg, per_func = analyzer.analyze_file(tree)
        assert per_func["foo"] == 1

    def test_branching_function(self):
        source = """
def bar(x):
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                print(i)
    else:
        while x < 0:
            x += 1
    return x
"""
        tree = ast.parse(source)
        agg, per_func = analyzer_result(tree)
        assert per_func["bar"] >= 4

    def test_boolean_operators_add_complexity(self):
        source = """
def check(a, b, c):
    if a and b or c:
        return True
    return False
"""
        tree = ast.parse(source)
        analyzer = ComplexityAnalyzer()
        _, per_func = analyzer.analyze_file(tree)
        # 1 (base) + 1 (if) + 2 (and + or)
        assert per_func["check"] >= 3

    def test_ternary_adds_complexity(self):
        source = "def tern(x):\n    return 1 if x else 0"
        tree = ast.parse(source)
        analyzer = ComplexityAnalyzer()
        _, per_func = analyzer.analyze_file(tree)
        assert per_func["tern"] >= 2

    def test_async_function(self):
        source = """
async def fetch(url):
    if url:
        return await get(url)
    return None
"""
        tree = ast.parse(source)
        analyzer = ComplexityAnalyzer()
        _, per_func = analyzer.analyze_file(tree)
        assert "fetch" in per_func
        assert per_func["fetch"] >= 2

    def test_multiple_functions(self):
        source = """
def a():
    pass

def b(x):
    if x:
        pass

def c(x, y):
    if x:
        if y:
            pass
"""
        tree = ast.parse(source)
        analyzer = ComplexityAnalyzer()
        agg, per_func = analyzer.analyze_file(tree)
        assert len(per_func) == 3
        assert agg == sum(per_func.values())


class TestComplexityGrade:
    def test_grade_a(self):
        assert ComplexityAnalyzer.complexity_grade(1) == "A"
        assert ComplexityAnalyzer.complexity_grade(10) == "A"

    def test_grade_b(self):
        assert ComplexityAnalyzer.complexity_grade(11) == "B"
        assert ComplexityAnalyzer.complexity_grade(20) == "B"

    def test_grade_c(self):
        assert ComplexityAnalyzer.complexity_grade(21) == "C"
        assert ComplexityAnalyzer.complexity_grade(50) == "C"

    def test_grade_f(self):
        assert ComplexityAnalyzer.complexity_grade(51) == "F"
        assert ComplexityAnalyzer.complexity_grade(100) == "F"


class TestRiskScore:
    def _make_result(self, findings_by_severity: dict[Severity, int]) -> ScanResult:
        findings = []
        for sev, count in findings_by_severity.items():
            for i in range(count):
                findings.append(Finding(
                    rule_id="TEST",
                    rule_name="Test",
                    severity=sev,
                    message="test",
                    location=Location(file_path="t.py", line_number=1, column_offset=0),
                ))
        return ScanResult(
            scan_id="test",
            timestamp="2026-01-01T00:00:00Z",
            files_analyzed=[FileAnalysis(file_path="t.py", findings=findings)],
            summary=ScanSummary(total_files=1, total_findings=len(findings)),
        )

    def test_zero_findings_zero_score(self):
        result = self._make_result({})
        assert compute_risk_score(result) == 0.0

    def test_critical_finding_weighted_10(self):
        result = self._make_result({Severity.CRITICAL: 1})
        assert compute_risk_score(result) == 10.0

    def test_mixed_severities(self):
        result = self._make_result({Severity.CRITICAL: 1, Severity.HIGH: 2, Severity.LOW: 3})
        # 10 + 10 + 3 = 23
        assert compute_risk_score(result) == 23.0

    def test_capped_at_100(self):
        result = self._make_result({Severity.CRITICAL: 20})
        assert compute_risk_score(result) == 100.0

    def test_complexity_penalty(self):
        result = self._make_result({})
        score_no_complexity = compute_risk_score(result, avg_complexity=5.0)
        score_with_complexity = compute_risk_score(result, avg_complexity=30.0)
        assert score_with_complexity > score_no_complexity


class TestRiskGrade:
    def test_grades(self):
        assert risk_grade(0) == "A"
        assert risk_grade(10) == "A"
        assert risk_grade(15) == "B"
        assert risk_grade(25) == "B"
        assert risk_grade(30) == "C"
        assert risk_grade(50) == "C"
        assert risk_grade(60) == "D"
        assert risk_grade(75) == "D"
        assert risk_grade(80) == "F"
        assert risk_grade(100) == "F"


def analyzer_result(tree):
    """Helper to create analyzer and return results."""
    analyzer = ComplexityAnalyzer()
    return analyzer.analyze_file(tree)
