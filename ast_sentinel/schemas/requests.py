
from pydantic import BaseModel, Field

from .findings import Severity


class ScanDirectoryRequest(BaseModel):
    directory_path: str
    recursive: bool = True
    exclude_patterns: list[str] = Field(default_factory=lambda: [".venv", "venv", "__pycache__", ".git"])

class ScanConfigOptions(BaseModel):
    enabled_rules: list[str] | None = None
    severity_threshold: Severity = Severity.INFO
