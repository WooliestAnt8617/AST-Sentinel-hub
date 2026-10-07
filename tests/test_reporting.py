import json

import pytest

from ast_sentinel.reporting.html_report import generate_html_report
from ast_sentinel.reporting.json_report import generate_json_report
from ast_sentinel.schemas.findings import (
    FileAnalysis,
    Finding,
    Location,
    ScanResult,
    ScanSummary,
    Severity,
)


@pytest.fixture
def sample_result() -> ScanResult:
    return ScanResult(
        scan_id="test-report-123",
        timestamp="2026-01-01T00:00:00Z",
        files_analyzed=[
            FileAnalysis(
                file_path="app.py",
                findings=[
                    Finding(
                        rule_id="SEC-001",
                        rule_name="Hardcoded Secrets",
                        severity=Severity.HIGH,
                        message="Hardcoded password found.",
                        location=Location(file_path="app.py", line_number=10, column_offset=0),
                        remediation="Use environment variables.",
                        code_snippet="PASSWORD = 'secret'",
                    )
                ],
                lines_of_code=50,
            )
        ],
        summary=ScanSummary(
            total_files=1,
            total_findings=1,
            high_count=1,
        ),
        risk_score=5.0,
    )


@pytest.fixture
def empty_result() -> ScanResult:
    return ScanResult(
        scan_id="test-clean-456",
        timestamp="2026-01-01T00:00:00Z",
        files_analyzed=[],
        summary=ScanSummary(),
        risk_score=0.0,
    )


class TestJSONReport:
    def test_generates_valid_json(self, sample_result):
        json_str = generate_json_report(sample_result)
        data = json.loads(json_str)
        assert data["scan_id"] == "test-report-123"

    def test_includes_findings(self, sample_result):
        json_str = generate_json_report(sample_result)
        data = json.loads(json_str)
        assert len(data["files_analyzed"][0]["findings"]) == 1

    def test_includes_risk_score(self, sample_result):
        json_str = generate_json_report(sample_result)
        data = json.loads(json_str)
        assert data["risk_score"] == 5.0

    def test_writes_to_file(self, sample_result, tmp_path):
        output = tmp_path / "report.json"
        generate_json_report(sample_result, output)
        assert output.exists()
        data = json.loads(output.read_text())
        assert data["scan_id"] == "test-report-123"

    def test_empty_result(self, empty_result):
        json_str = generate_json_report(empty_result)
        data = json.loads(json_str)
        assert data["summary"]["total_findings"] == 0


class TestHTMLReport:
    def test_generates_html(self, sample_result):
        html = generate_html_report(sample_result)
        assert "<!DOCTYPE html>" in html
        assert "AST-Sentinel" in html

    def test_contains_finding_details(self, sample_result):
        html = generate_html_report(sample_result)
        assert "Hardcoded Secrets" in html
        assert "Hardcoded password found." in html

    def test_contains_risk_grade(self, sample_result):
        html = generate_html_report(sample_result)
        # Risk score 5.0 → grade A
        assert ">A<" in html

    def test_shows_no_findings_for_clean(self, empty_result):
        html = generate_html_report(empty_result)
        assert "No security findings detected" in html

    def test_writes_to_file(self, sample_result, tmp_path):
        output = tmp_path / "report.html"
        generate_html_report(sample_result, output)
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "AST-Sentinel" in content

    def test_severity_css_classes(self, sample_result):
        html = generate_html_report(sample_result)
        assert "HIGH" in html
