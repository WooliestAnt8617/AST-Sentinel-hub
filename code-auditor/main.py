"""
Code Intelligence Platform — FastAPI application entry point.
Provides code auditing via Google Gemini and aggregate analytics.
"""

import json
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from database import init_db, get_db, save_audit, get_audit
from services.auditor import audit_code, audit_code_with_requirements
from services.analytics import get_full_analytics
from services.file_handler import detect_language, extract_zip, build_file_tree

# ── App Setup ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Code Intelligence Platform",
    description="AI-powered code auditing and analytics",
    version="1.0.0",
)

BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.on_event("startup")
async def startup():
    """Initialize the database on application startup."""
    await init_db()


# ── Pages ──────────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    """Landing page with hero section and feature cards."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) as count FROM audits")
        row = await cursor.fetchone()
        total_audits = row["count"]
    finally:
        await db.close()

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "total_audits": total_audits},
    )


@app.get("/audit", response_class=HTMLResponse)
async def audit_form_page(request: Request):
    """Audit input form page."""
    return templates.TemplateResponse("audit_form.html", {"request": request})


@app.get("/audit/{audit_id}", response_class=HTMLResponse)
async def audit_results_page(request: Request, audit_id: str):
    """View audit results for a specific audit."""
    db = await get_db()
    try:
        audit = await get_audit(db, audit_id)
    finally:
        await db.close()

    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    # Parse raw_response for additional data
    raw = {}
    if audit.get("raw_response"):
        try:
            raw = json.loads(audit["raw_response"])
        except json.JSONDecodeError:
            pass

    # Group findings by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    grouped_findings = {}
    for sev in severity_order:
        findings = [f for f in audit.get("findings", []) if f["severity"] == sev]
        if findings:
            grouped_findings[sev] = findings

    return templates.TemplateResponse(
        "audit_results.html",
        {
            "request": request,
            "audit": audit,
            "grouped_findings": grouped_findings,
            "severity_order": severity_order,
            "raw": raw,
        },
    )


@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request):
    """Analytics dashboard page."""
    return templates.TemplateResponse("analytics.html", {"request": request})


@app.get("/audit/standards", response_class=HTMLResponse)
async def standards_form_page(request: Request):
    """Standards & Requirements audit input form page."""
    return templates.TemplateResponse("standards_form.html", {"request": request})


@app.get("/audit/standards/{audit_id}", response_class=HTMLResponse)
async def standards_results_page(request: Request, audit_id: str):
    """View standards audit results for a specific audit."""
    db = await get_db()
    try:
        audit = await get_audit(db, audit_id)
    finally:
        await db.close()

    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    # Parse raw_response for additional data (requirements_checklist, standards_summary)
    raw = {}
    if audit.get("raw_response"):
        try:
            raw = json.loads(audit["raw_response"])
        except json.JSONDecodeError:
            pass

    # Group findings by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    grouped_findings = {}
    for sev in severity_order:
        findings = [f for f in audit.get("findings", []) if f["severity"] == sev]
        if findings:
            grouped_findings[sev] = findings

    # Parse audit requirements
    audit_requirements = {}
    if audit.get("audit_requirements"):
        try:
            audit_requirements = json.loads(audit["audit_requirements"])
        except json.JSONDecodeError:
            pass

    return templates.TemplateResponse(
        "standards_results.html",
        {
            "request": request,
            "audit": audit,
            "grouped_findings": grouped_findings,
            "severity_order": severity_order,
            "raw": raw,
            "audit_requirements": audit_requirements,
            "requirements_checklist": raw.get("requirements_checklist", []),
            "standards_summary": raw.get("standards_summary", ""),
        },
    )


# ── API Endpoints ──────────────────────────────────────────────────────────────


@app.post("/audit/paste")
async def audit_paste(request: Request, code: str = Form(...), filename: str = Form(None)):
    """Submit pasted code for AI audit."""
    if not code or not code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty")

    if len(code) > 100_000:
        raise HTTPException(
            status_code=400, detail="Code exceeds maximum length of 100,000 characters"
        )

    # Detect language
    language = detect_language(filename=filename, code=code)

    try:
        # Run AI audit
        result = audit_code(code, filename=filename, language_hint=language)
        # Handle both sync and async
        if hasattr(result, "__await__"):
            result = await result
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Create audit record
    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "language": result.get("language", language),
        "filename": filename,
        "source_type": "paste",
        "code_length": len(code),
        "scores": result.get("scores", {}),
        "complexity_level": result.get("complexity_level", "intermediate"),
        "summary": result.get("summary", ""),
        "findings": result.get("findings", []),
        "topics_detected": result.get("topics_detected", []),
        "raw_response": json.dumps(result),
    }

    # Save to database
    db = await get_db()
    try:
        await save_audit(db, audit_data)
    finally:
        await db.close()

    return RedirectResponse(url=f"/audit/{audit_id}", status_code=303)


@app.post("/audit/standards")
async def audit_standards(
    request: Request,
    code: str = Form(...),
    filename: str = Form(None),
    language_standard: str = Form(""),
    security_framework: str = Form(""),
    complexity_threshold: str = Form(""),
    naming_convention: str = Form(""),
    additional_notes: str = Form(""),
):
    """Submit code for a requirements-aware standards audit."""
    if not code or not code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty")

    if len(code) > 100_000:
        raise HTTPException(
            status_code=400, detail="Code exceeds maximum length of 100,000 characters"
        )

    # Require at least one requirement field
    requirements = {
        "language_standard": language_standard.strip(),
        "security_framework": security_framework.strip(),
        "complexity_threshold": complexity_threshold.strip(),
        "naming_convention": naming_convention.strip(),
        "additional_notes": additional_notes.strip(),
    }
    if not any(requirements.values()):
        raise HTTPException(
            status_code=400,
            detail="Please specify at least one audit requirement."
        )

    # Detect language
    language = detect_language(filename=filename, code=code)

    try:
        result = audit_code_with_requirements(
            code, requirements, filename=filename, language_hint=language
        )
        if hasattr(result, "__await__"):
            result = await result
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Create audit record
    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "language": result.get("language", language),
        "filename": filename,
        "source_type": "standards",
        "code_length": len(code),
        "scores": result.get("scores", {}),
        "complexity_level": result.get("complexity_level", "intermediate"),
        "summary": result.get("summary", ""),
        "findings": result.get("findings", []),
        "topics_detected": result.get("topics_detected", []),
        "audit_requirements": json.dumps(requirements),
        "raw_response": json.dumps(result),
    }

    # Save to database
    db = await get_db()
    try:
        await save_audit(db, audit_data)
    finally:
        await db.close()

    return RedirectResponse(url=f"/audit/standards/{audit_id}", status_code=303)


@app.post("/audit/standards/file")
async def audit_standards_file(
    request: Request,
    file: UploadFile = File(...),
    language_standard: str = Form(""),
    security_framework: str = Form(""),
    complexity_threshold: str = Form(""),
    naming_convention: str = Form(""),
    additional_notes: str = Form(""),
):
    """Upload a single source file for standards audit."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    file_bytes = await file.read()
    if len(file_bytes) > 100_000:
        raise HTTPException(status_code=400, detail="File exceeds 100KB limit.")

    try:
        code = file_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read file as text.")

    if not code.strip():
        raise HTTPException(status_code=400, detail="File is empty.")

    requirements = {
        "language_standard": language_standard.strip(),
        "security_framework": security_framework.strip(),
        "complexity_threshold": complexity_threshold.strip(),
        "naming_convention": naming_convention.strip(),
        "additional_notes": additional_notes.strip(),
    }
    if not any(requirements.values()):
        raise HTTPException(status_code=400, detail="Please specify at least one audit requirement.")

    language = detect_language(filename=file.filename, code=code)

    try:
        result = audit_code_with_requirements(code, requirements, filename=file.filename, language_hint=language)
        if hasattr(result, "__await__"):
            result = await result
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "language": result.get("language", language),
        "filename": file.filename,
        "source_type": "standards-file",
        "code_length": len(code),
        "scores": result.get("scores", {}),
        "complexity_level": result.get("complexity_level", "intermediate"),
        "summary": result.get("summary", ""),
        "findings": result.get("findings", []),
        "topics_detected": result.get("topics_detected", []),
        "audit_requirements": json.dumps(requirements),
        "raw_response": json.dumps(result),
    }
    db = await get_db()
    try:
        await save_audit(db, audit_data)
    finally:
        await db.close()
    return RedirectResponse(url=f"/audit/standards/{audit_id}", status_code=303)


@app.post("/audit/standards/zip")
async def audit_standards_zip(
    request: Request,
    file: UploadFile = File(...),
    language_standard: str = Form(""),
    security_framework: str = Form(""),
    complexity_threshold: str = Form(""),
    naming_convention: str = Form(""),
    additional_notes: str = Form(""),
):
    """Upload a ZIP archive for multi-file standards audit."""
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted.")

    file_bytes = await file.read()
    if len(file_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File exceeds 10MB limit.")

    try:
        extracted = extract_zip(file_bytes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    requirements = {
        "language_standard": language_standard.strip(),
        "security_framework": security_framework.strip(),
        "complexity_threshold": complexity_threshold.strip(),
        "naming_convention": naming_convention.strip(),
        "additional_notes": additional_notes.strip(),
    }
    if not any(requirements.values()):
        raise HTTPException(status_code=400, detail="Please specify at least one audit requirement.")

    # Audit each file against the requirements
    all_findings, all_topics = [], set()
    total_scores = {"security": [], "accessibility": [], "performance": [], "maintainability": [], "overall": [], "standards": []}
    all_checklists, file_results, errors = [], [], []

    for ef in extracted:
        try:
            result = audit_code_with_requirements(
                ef["content"], requirements,
                filename=ef["filename"], language_hint=ef["language"]
            )
            if hasattr(result, "__await__"):
                result = await result

            file_results.append({
                "filename": ef["filename"],
                "language": result.get("language", ef["language"]),
                "summary": result.get("summary", ""),
                "scores": result.get("scores", {}),
                "findings_count": len(result.get("findings", [])),
                "checklist_pass": sum(1 for c in result.get("requirements_checklist", []) if c["status"] == "pass"),
                "checklist_total": len(result.get("requirements_checklist", [])),
            })

            for finding in result.get("findings", []):
                finding["source_file"] = ef["filename"]
                all_findings.append(finding)

            for topic in result.get("topics_detected", []):
                all_topics.add(topic)

            for key in total_scores:
                if key in result.get("scores", {}):
                    total_scores[key].append(result["scores"][key])

            # Merge checklists — keep worst status per requirement
            for item in result.get("requirements_checklist", []):
                all_checklists.append(item)

        except Exception as e:
            errors.append({"filename": ef["filename"], "error": str(e)})

    avg_scores = {k: round(sum(v) / len(v)) if v else 50 for k, v in total_scores.items()}

    # Deduplicate checklist — worst status wins
    STATUS_RANK = {"pass": 0, "partial": 1, "fail": 2}
    deduped: dict[str, dict] = {}
    for item in all_checklists:
        key = item["requirement"]
        if key not in deduped or STATUS_RANK.get(item["status"], 0) > STATUS_RANK.get(deduped[key]["status"], 0):
            deduped[key] = item
    merged_checklist = list(deduped.values())

    languages = [ef["language"] for ef in extracted]
    most_common_lang = max(set(languages), key=languages.count) if languages else "unknown"

    aggregate_result = {
        "language": most_common_lang,
        "summary": f"ZIP standards audit of {file.filename}: analyzed {len(extracted)} files.",
        "findings": all_findings,
        "scores": avg_scores,
        "topics_detected": list(all_topics),
        "complexity_level": "advanced" if len(extracted) > 5 else "intermediate",
        "requirements_checklist": merged_checklist,
        "standards_summary": f"Audited {len(extracted)} files against your requirements. Average standards compliance: {avg_scores.get('standards', 0)}/100.",
        "file_results": file_results,
        "errors": errors,
    }

    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "language": most_common_lang,
        "filename": file.filename,
        "source_type": "standards-zip",
        "code_length": sum(ef["size"] for ef in extracted),
        "scores": avg_scores,
        "complexity_level": aggregate_result["complexity_level"],
        "summary": aggregate_result["summary"],
        "findings": all_findings,
        "topics_detected": list(all_topics),
        "audit_requirements": json.dumps(requirements),
        "raw_response": json.dumps(aggregate_result),
    }
    db = await get_db()
    try:
        await save_audit(db, audit_data)
    finally:
        await db.close()
    return RedirectResponse(url=f"/audit/standards/{audit_id}", status_code=303)


@app.post("/audit/standards/github")
async def audit_standards_github(
    request: Request,
    github_url: str = Form(...),
    language_standard: str = Form(""),
    security_framework: str = Form(""),
    complexity_threshold: str = Form(""),
    naming_convention: str = Form(""),
    additional_notes: str = Form(""),
):
    """Fetch a GitHub file or repo and run a standards audit."""
    github_url = github_url.strip()
    if not github_url:
        raise HTTPException(status_code=400, detail="GitHub URL is required.")

    requirements = {
        "language_standard": language_standard.strip(),
        "security_framework": security_framework.strip(),
        "complexity_threshold": complexity_threshold.strip(),
        "naming_convention": naming_convention.strip(),
        "additional_notes": additional_notes.strip(),
    }
    if not any(requirements.values()):
        raise HTTPException(status_code=400, detail="Please specify at least one audit requirement.")

    # Convert GitHub web URLs to raw content URLs
    raw_url, detected_filename = _github_url_to_raw(github_url)
    if not raw_url:
        raise HTTPException(
            status_code=400,
            detail="Could not parse GitHub URL. Please use a direct file URL (github.com/user/repo/blob/branch/file.py) or a raw URL."
        )

    # Fetch the file content
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            headers = {"Accept": "text/plain", "User-Agent": "AST-Sentinel/1.0"}
            resp = await client.get(raw_url, headers=headers)
            resp.raise_for_status()
            code = resp.text
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="GitHub request timed out. Please try again.")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=400, detail=f"Could not fetch file from GitHub: HTTP {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch from GitHub: {str(e)}")

    if not code.strip():
        raise HTTPException(status_code=400, detail="The fetched file is empty.")
    if len(code) > 100_000:
        raise HTTPException(status_code=400, detail="File exceeds 100,000 character limit.")

    language = detect_language(filename=detected_filename, code=code)

    try:
        result = audit_code_with_requirements(code, requirements, filename=detected_filename, language_hint=language)
        if hasattr(result, "__await__"):
            result = await result
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "language": result.get("language", language),
        "filename": detected_filename or github_url,
        "source_type": "standards-github",
        "code_length": len(code),
        "scores": result.get("scores", {}),
        "complexity_level": result.get("complexity_level", "intermediate"),
        "summary": result.get("summary", ""),
        "findings": result.get("findings", []),
        "topics_detected": result.get("topics_detected", []),
        "audit_requirements": json.dumps(requirements),
        "raw_response": json.dumps({**result, "github_url": github_url}),
    }
    db = await get_db()
    try:
        await save_audit(db, audit_data)
    finally:
        await db.close()
    return RedirectResponse(url=f"/audit/standards/{audit_id}", status_code=303)


def _github_url_to_raw(url: str) -> tuple[str | None, str | None]:
    """
    Convert various GitHub URL formats to raw content URLs.

    Supported formats:
    - https://github.com/user/repo/blob/branch/path/to/file.py  → raw.githubusercontent.com
    - https://raw.githubusercontent.com/...                      → unchanged
    - https://github.com/user/repo/raw/branch/path/to/file.py   → unchanged path pattern
    - https://gist.github.com/user/gist_id                       → raw gist
    """
    # Already a raw URL
    if "raw.githubusercontent.com" in url:
        filename = url.rstrip("/").split("/")[-1]
        return url, filename

    # github.com/user/repo/blob/branch/path
    blob_match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", url
    )
    if blob_match:
        user, repo, branch, path = blob_match.groups()
        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
        filename = path.split("/")[-1]
        return raw_url, filename

    # github.com/user/repo/raw/branch/path (alternate)
    raw_match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.+)", url
    )
    if raw_match:
        user, repo, branch, path = raw_match.groups()
        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
        filename = path.split("/")[-1]
        return raw_url, filename

    # Gist raw: gist.github.com/user/id → try raw redirect
    gist_match = re.match(r"https?://gist\.github\.com/([^/]+)/([a-f0-9]+)", url)
    if gist_match:
        user, gist_id = gist_match.groups()
        raw_url = f"https://gist.githubusercontent.com/{user}/{gist_id}/raw"
        return raw_url, f"gist_{gist_id[:8]}.txt"

    return None, None



@app.get("/api/analytics")
async def api_analytics():
    """JSON API for analytics data (consumed by Chart.js)."""
    db = await get_db()
    try:
        data = await get_full_analytics(db)
    finally:
        await db.close()
    return JSONResponse(content=data)

@app.get("/api/audit/{audit_id}/export")
async def export_audit(audit_id: str):
    """Export audit results as JSON."""
    db = await get_db()
    try:
        audit = await get_audit(db, audit_id)
    finally:
        await db.close()

    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    return JSONResponse(content=audit)


