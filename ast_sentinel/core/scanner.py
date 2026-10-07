import uuid
from datetime import datetime, timezone
from pathlib import Path

from ast_sentinel.core.parser import ParsingError, parse_file, parse_source
from ast_sentinel.core.registry import get_registry
from ast_sentinel.core.visitor import PythonAstRuleVisitor
from ast_sentinel.schemas.findings import FileAnalysis, Finding, ScanResult, ScanSummary


class ScannerOrchestrator:
    def __init__(self):
        self.registry = get_registry()

    def scan_source(self, source: str, filename: str) -> FileAnalysis:
        try:
            tree = parse_source(source, filename)
            lines = source.splitlines()
        except ParsingError:
            return FileAnalysis(
                file_path=filename,
                findings=[],
                lines_of_code=len(source.splitlines())
            )

        return self._run_analysis(tree, lines, filename)

    def scan_file(self, path: Path) -> FileAnalysis:
        try:
            tree, lines = parse_file(path)
        except ParsingError:
            return FileAnalysis(file_path=str(path), findings=[], lines_of_code=0)

        return self._run_analysis(tree, lines, str(path))

    def _run_analysis(self, tree, lines: list[str], filename: str) -> FileAnalysis:
        all_findings: list[Finding] = []
        rules = self.registry.get_all_rules()

        for rule_id, rule_class in rules.items():
            if issubclass(rule_class, PythonAstRuleVisitor):
                visitor = rule_class()
                try:
                    findings = visitor.analyze(tree, lines, filename)
                    all_findings.extend(findings)
                except Exception:
                    pass

        return FileAnalysis(
            file_path=filename,
            findings=all_findings,
            lines_of_code=len(lines)
        )

    def scan_directory(self, directory_path: str, recursive: bool = True, exclude: list[str] | None = None) -> ScanResult:
        if exclude is None:
            exclude = [".venv", "venv", "__pycache__", ".git"]

        path = Path(directory_path)
        files_to_scan = []

        if path.is_file():
            files_to_scan.append(path)
        elif path.is_dir():
            if recursive:
                for p in path.rglob("*.py"):
                    if not any(ex in p.parts for ex in exclude):
                        files_to_scan.append(p)
            else:
                for p in path.glob("*.py"):
                    if not any(ex in p.parts for ex in exclude):
                        files_to_scan.append(p)

        files_analyzed = []
        for file_path in files_to_scan:
            analysis = self.scan_file(file_path)
            files_analyzed.append(analysis)

        summary = self._build_summary(files_analyzed)

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            files_analyzed=files_analyzed,
            summary=summary,
            risk_score=None
        )

    @staticmethod
    def _build_summary(analyses: list[FileAnalysis]) -> ScanSummary:
        total_findings = sum(len(fa.findings) for fa in analyses)
        critical = sum(sum(1 for f in fa.findings if f.severity.value == "CRITICAL") for fa in analyses)
        high = sum(sum(1 for f in fa.findings if f.severity.value == "HIGH") for fa in analyses)
        medium = sum(sum(1 for f in fa.findings if f.severity.value == "MEDIUM") for fa in analyses)
        low = sum(sum(1 for f in fa.findings if f.severity.value == "LOW") for fa in analyses)
        info = sum(sum(1 for f in fa.findings if f.severity.value == "INFO") for fa in analyses)

        return ScanSummary(
            total_files=len(analyses),
            total_findings=total_findings,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info
        )
