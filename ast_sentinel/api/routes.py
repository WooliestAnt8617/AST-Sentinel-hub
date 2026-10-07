import ast
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ast_sentinel.core.scanner import ScannerOrchestrator
from ast_sentinel.metrics.complexity import ComplexityAnalyzer
from ast_sentinel.metrics.risk_score import compute_risk_score
from ast_sentinel.reporting.html_report import generate_html_report
from ast_sentinel.schemas.findings import ScanResult
from ast_sentinel.schemas.requests import ScanDirectoryRequest
from ast_sentinel.schemas.responses import HealthResponse, ScanResponse

router = APIRouter()

# In-memory store (will be backed by SQLite in DB layer)
_scan_store: dict[str, ScanResult] = {}


class SourceSubmission(BaseModel):
    source: str
    filename: str = "<uploaded>"


@router.get("/health", response_model=HealthResponse)
async def health():
    from ast_sentinel.core.registry import get_registry
    registry = get_registry()
    return HealthResponse(
        status="ok",
        version="0.1.0",
        rules_loaded=len(registry.get_all_rules()),
    )


@router.post("/api/v1/scan/file", response_model=ScanResponse)
async def scan_uploaded_file(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files are accepted.")

    start = time.perf_counter()
    content = await file.read()
    source = content.decode("utf-8", errors="replace")

    scanner = ScannerOrchestrator()
    analysis = scanner.scan_source(source, file.filename)

    result = ScanResult(
        scan_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        files_analyzed=[analysis],
        summary=ScannerOrchestrator._build_summary([analysis]),
        risk_score=None,
    )
    # Compute complexity + risk
    try:
        tree = ast.parse(source)
        agg, _ = ComplexityAnalyzer().analyze_file(tree)
    except Exception:
        agg = 0
    result.risk_score = compute_risk_score(result, float(agg))

    duration_ms = int((time.perf_counter() - start) * 1000)
    _scan_store[result.scan_id] = result

    return ScanResponse(status="completed", duration_ms=duration_ms, result=result)


@router.post("/api/v1/scan/directory", response_model=ScanResponse)
async def scan_directory(req: ScanDirectoryRequest):
    path = Path(req.directory_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {req.directory_path}")

    start = time.perf_counter()
    scanner = ScannerOrchestrator()
    result = scanner.scan_directory(req.directory_path, req.recursive, req.exclude_patterns)
    result.risk_score = compute_risk_score(result)

    duration_ms = int((time.perf_counter() - start) * 1000)
    _scan_store[result.scan_id] = result

    return ScanResponse(status="completed", duration_ms=duration_ms, result=result)


@router.post("/api/v1/scan/source", response_model=ScanResponse)
async def scan_source(submission: SourceSubmission):
    start = time.perf_counter()
    scanner = ScannerOrchestrator()
    analysis = scanner.scan_source(submission.source, submission.filename)

    result = ScanResult(
        scan_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        files_analyzed=[analysis],
        summary=ScannerOrchestrator._build_summary([analysis]),
        risk_score=None,
    )
    try:
        tree = ast.parse(submission.source)
        agg, _ = ComplexityAnalyzer().analyze_file(tree)
    except Exception:
        agg = 0
    result.risk_score = compute_risk_score(result, float(agg))

    duration_ms = int((time.perf_counter() - start) * 1000)
    _scan_store[result.scan_id] = result

    return ScanResponse(status="completed", duration_ms=duration_ms, result=result)


@router.get("/api/v1/report/{scan_id}")
async def get_report_json(scan_id: str):
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return _scan_store[scan_id]


@router.get("/api/v1/report/{scan_id}/html")
async def get_report_html(scan_id: str):
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Scan not found.")
    html = generate_html_report(_scan_store[scan_id])
    return HTMLResponse(content=html)
