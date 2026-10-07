from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Location(BaseModel):
    file_path: str
    line_number: int
    column_offset: int
    end_line_number: int | None = None
    end_column_offset: int | None = None

class Finding(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    message: str
    location: Location
    code_snippet: str | None = None
    remediation: str | None = None
    cwe_id: str | None = None

class FileAnalysis(BaseModel):
    file_path: str
    findings: list[Finding] = Field(default_factory=list)
    complexity_score: int | None = None
    lines_of_code: int | None = None

class ScanSummary(BaseModel):
    total_files: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    files_analyzed: list[FileAnalysis] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    risk_score: float | None = None
