from pydantic import BaseModel

from .findings import ScanResult


class ScanResponse(BaseModel):
    status: str
    duration_ms: int
    result: ScanResult

class HealthResponse(BaseModel):
    status: str
    version: str
    rules_loaded: int

class ErrorResponse(BaseModel):
    detail: str
    error_code: str
