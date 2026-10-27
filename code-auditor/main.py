"""
AST-Sentinel: Code Auditor — AI-powered code auditing & analytics web platform.
Provides deep code analysis via Google Gemini and aggregate security analytics.
Part of the AST-Sentinel security auditing ecosystem.
"""

import json
import uuid
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

# Ensure code-auditor directory is in sys.path for direct script/submodule execution
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from urllib.parse import urlparse
import httpx
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

# Load environment variables
load_dotenv(BASE_DIR / ".env", override=True)
load_dotenv(override=True)

from database import init_db, get_db, save_audit, get_audit, create_user, get_user_by_username, get_user_by_id, _verify_password
from services.auditor import audit_code, audit_code_with_requirements
from services.analytics import get_full_analytics
from services.file_handler import detect_language, extract_zip, build_file_tree
from services.auth import create_session_token, decode_session_token, SESSION_COOKIE

# ── App Setup ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app_: FastAPI):
    """Application lifespan: initialize DB on startup."""
    await init_db()
    yield


app = FastAPI(
    title="AST-Sentinel: Code Auditor",
    description="AI-powered code auditing and analytics — Web interface for AST-Sentinel",
    version="1.0.0",
    lifespan=lifespan,
)

BASE_DIR = Path(__file__).parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.exception_handler(StarletteHTTPException)
@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Render a styled HTML error page for browsers, or JSON for API calls."""
    accept = request.headers.get("accept", "")
    if "application/json" in accept or request.url.path.startswith("/api/"):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    user = await get_current_user(request)
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "current_user": user,
        },
        status_code=exc.status_code,
    )


# ── Auth Enforcement Middleware ───────────────────────────────────────────

@app.middleware("http")
async def require_auth_middleware(request: Request, call_next):
    """
    Ensure non-signed in users can ONLY access the home page, login, signup, and static assets.
    All other pages redirect to /login; API routes return 401 Unauthorized.
    """
    path = request.url.path
    # Publicly accessible routes
    if (
        path == "/"
        or path.startswith("/login")
        or path.startswith("/signup")
        or path.startswith("/static")
        or path.startswith("/download")
        or path == "/favicon.ico"
    ):
        return await call_next(request)

    # Check session token
    token = request.cookies.get(SESSION_COOKIE)
    user_id = decode_session_token(token) if token else None
    if not user_id:
        if path.startswith("/api/"):
            return JSONResponse(status_code=401, content={"error": "Authentication required"})
        return RedirectResponse(url="/login", status_code=303)

    return await call_next(request)



# ── Auth Helpers ────────────────────────────────────────────────────────────

async def get_current_user(request: Request) -> dict | None:
    """Read session cookie and return the user dict, or None if not logged in."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    user_id = decode_session_token(token)
    if not user_id:
        return None
    db = await get_db()
    try:
        return await get_user_by_id(db, user_id)
    finally:
        await db.close()


async def ctx(request: Request, extra: dict | None = None) -> dict:
    """Build a base template context with current_user injected."""
    user = await get_current_user(request)
    base = {"request": request, "current_user": user}
    if extra:
        base.update(extra)
    return base


# ── Pages ─────────────────────────────────────────────────────────────────

# ── Auth Routes ───────────────────────────────────────────────────────────

@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", await ctx(request))


@app.post("/signup", response_class=HTMLResponse)
async def signup_post(request: Request, username: str = Form(...), email: str = Form(...),
                      password: str = Form(...), confirm: str = Form(...)):
    error = None
    if len(username.strip()) < 3:
        error = "Username must be at least 3 characters."
    elif len(password) < 8:
        error = "Password must be at least 8 characters."
    elif password != confirm:
        error = "Passwords do not match."
    else:
        db = await get_db()
        try:
            user = await create_user(db, username, email, password)
        except ValueError as e:
            error = str(e)
        finally:
            await db.close()
        if not error:
            response = RedirectResponse(url="/login?signup=1", status_code=303)
            return response
    return templates.TemplateResponse("signup.html", await ctx(request, {"error": error, "username": username, "email": email}))


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, signup: str = ""):
    extra = {"success": "Account created! Please sign in."} if signup == "1" else {}
    return templates.TemplateResponse("login.html", await ctx(request, extra))


@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    db = await get_db()
    try:
        user = await get_user_by_username(db, username)
    finally:
        await db.close()
    if not user or not _verify_password(password, user["password_hash"]):
        return templates.TemplateResponse("login.html", await ctx(request, {"error": "Invalid username or password.", "username": username}))
    token = create_session_token(user["id"])
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(SESSION_COOKIE, token, max_age=60 * 60 * 24 * 30, httponly=True, samesite="lax")
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/download", response_class=HTMLResponse)
async def download_page(request: Request):
    """CLI download page."""
    user = await get_current_user(request)
    exe_path = BASE_DIR / "static" / "bin" / "ast-sentinel.exe"
    exe_size_mb = round(exe_path.stat().st_size / (1024 * 1024), 1) if exe_path.exists() else 0
    return templates.TemplateResponse(
        "download.html",
        {
            "request": request,
            "current_user": user,
            "active_page": "download",
            "exe_size_mb": exe_size_mb,
            "exe_available": exe_path.exists(),
        },
    )


@app.get("/download/cli")
async def download_cli():
    """Serve the ast-sentinel CLI executable for download."""
    exe_path = BASE_DIR / "static" / "bin" / "ast-sentinel.exe"
    if not exe_path.exists():
        raise HTTPException(status_code=404, detail="CLI executable not yet built. Run scripts/build_cli.py first.")
    return FileResponse(
        path=str(exe_path),
        filename="ast-sentinel.exe",
        media_type="application/octet-stream",
    )


@app.get("/", response_class=HTMLResponse)
async def landing_page(request: Request):
    """Landing page with hero section and feature cards."""
    user = await get_current_user(request)
    total_audits = 0
    if user:
        db = await get_db()
        try:
            cursor = await db.execute(
                "SELECT COUNT(*) as count FROM audits WHERE user_id = ?",
                (user["id"],),
            )
            row = await cursor.fetchone()
            total_audits = row["count"] if row else 0
        finally:
            await db.close()

    return templates.TemplateResponse(
        "index.html",
        {"request": request, "current_user": user, "total_audits": total_audits, "active_page": "home"},
    )


@app.get("/audit", response_class=HTMLResponse)
async def audit_form_page(request: Request):
    """Audit input form page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("audit_form.html", {"request": request, "current_user": user, "active_page": "audit"})


@app.get("/audit/standards", response_class=HTMLResponse)
async def standards_form_page(request: Request):
    """Standards & Requirements audit input form page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("standards_form.html", {"request": request, "current_user": user, "active_page": "standards"})


@app.get("/audit/standards/{audit_id}", response_class=HTMLResponse)
async def standards_results_page(request: Request, audit_id: str):
    """View standards audit results for a specific audit."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    db = await get_db()
    try:
        audit = await get_audit(db, audit_id)
    finally:
        await db.close()

    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    if audit.get("user_id") and audit.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

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
            "current_user": user,
            "audit": audit,
            "grouped_findings": grouped_findings,
            "severity_order": severity_order,
            "raw": raw,
            "audit_requirements": audit_requirements,
            "requirements_checklist": raw.get("requirements_checklist", []),
            "standards_summary": raw.get("standards_summary", ""),
        },
    )


@app.get("/audit/{audit_id}", response_class=HTMLResponse)
async def audit_results_page(request: Request, audit_id: str):
    """View audit results for a specific audit."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    db = await get_db()
    try:
        audit = await get_audit(db, audit_id)
    finally:
        await db.close()

    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    if audit.get("user_id") and audit.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

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
            "current_user": user,
            "audit": audit,
            "grouped_findings": grouped_findings,
            "severity_order": severity_order,
            "raw": raw,
        },
    )


@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request):
    """Analytics dashboard page."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("analytics.html", {"request": request, "current_user": user, "active_page": "analytics"})


# ── API Endpoints ──────────────────────────────────────────────────────────────


@app.post("/audit/paste")
async def audit_paste(request: Request, code: str = Form(...), filename: str = Form(None)):
    """Submit pasted code for AI audit."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
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
        result = await audit_code(code, filename=filename, language_hint=language)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Create audit record
    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "user_id": user["id"],
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


@app.post("/audit/upload")
async def audit_upload(request: Request, file: UploadFile = File(...)):
    """Upload a ZIP archive for code audit."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files are accepted.")

    file_bytes = await file.read()
    if len(file_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File exceeds 10MB limit.")

    try:
        extracted = extract_zip(file_bytes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not extracted:
        raise HTTPException(status_code=400, detail="No valid source files found in archive.")

    all_findings, all_topics = [], set()
    total_scores = {"security": [], "accessibility": [], "performance": [], "maintainability": [], "overall": []}
    file_results = []

    for ef in extracted:
        try:
            result = await audit_code(ef["content"], filename=ef["filename"], language_hint=ef["language"])
            file_results.append({
                "filename": ef["filename"],
                "language": result.get("language", ef["language"]),
                "summary": result.get("summary", ""),
                "scores": result.get("scores", {}),
                "findings_count": len(result.get("findings", [])),
            })
            for finding in result.get("findings", []):
                finding["source_file"] = ef["filename"]
                all_findings.append(finding)
            for topic in result.get("topics_detected", []):
                all_topics.add(topic)
            for key in total_scores:
                if key in result.get("scores", {}):
                    total_scores[key].append(result["scores"][key])
        except Exception:
            continue

    avg_scores = {k: round(sum(v) / len(v)) if v else 50 for k, v in total_scores.items()}
    languages = [ef["language"] for ef in extracted]
    most_common_lang = max(set(languages), key=languages.count) if languages else "unknown"

    aggregate_result = {
        "language": most_common_lang,
        "summary": f"ZIP archive audit of {file.filename}: analyzed {len(extracted)} files.",
        "findings": all_findings,
        "scores": avg_scores,
        "topics_detected": list(all_topics),
        "complexity_level": "advanced" if len(extracted) > 5 else "intermediate",
        "file_results": file_results,
    }

    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "user_id": user["id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "language": most_common_lang,
        "filename": file.filename,
        "source_type": "zip",
        "code_length": sum(ef["size"] for ef in extracted),
        "scores": avg_scores,
        "complexity_level": aggregate_result["complexity_level"],
        "summary": aggregate_result["summary"],
        "findings": all_findings,
        "topics_detected": list(all_topics),
        "raw_response": json.dumps(aggregate_result),
    }
    db = await get_db()
    try:
        await save_audit(db, audit_data)
    finally:
        await db.close()

    return RedirectResponse(url=f"/audit/{audit_id}", status_code=303)


# ── GitHub Integration Helpers ────────────────────────────────────────────────

def _parse_github_url(url: str) -> dict | None:
    """
    Parse any GitHub URL: whole repositories, branches, single files, raw URLs, and gists.

    Supported formats:
    - https://github.com/owner/repo (or github.com/owner/repo)
    - https://github.com/owner/repo/tree/branch
    - https://github.com/owner/repo/blob/branch/path/to/file.py
    - https://github.com/owner/repo/raw/branch/path/to/file.py
    - https://raw.githubusercontent.com/owner/repo/branch/path/to/file.py
    - https://gist.github.com/owner/gist_id

    Returns:
      {
        "kind": "repo" | "file",
        "url": str,         # zipball archive URL for repos, raw text URL for files
        "filename": str,    # detected filename or repo name
        "repo": str | None, # "owner/repo"
        "branch": str | None,
      }
      or None if unparseable.
    """
    if not url:
        return None
    url = url.strip()

    # Strip git+ prefix
    url = re.sub(r"^git\+", "", url)

    # Strip fragments (#L1-L20) and query parameters (?raw=true)
    clean_url = url.split("#")[0].split("?")[0].rstrip("/")

    # Ensure http/https scheme
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    parsed = urlparse(clean_url)
    host = parsed.netloc.lower()
    path = parsed.path.strip("/")

    # 1. Direct raw file: raw.githubusercontent.com/user/repo/branch/filepath...
    if host == "raw.githubusercontent.com":
        parts = path.split("/", 3)
        if len(parts) >= 4:
            user, repo, branch, filepath = parts
            filename = filepath.split("/")[-1]
            return {
                "kind": "file",
                "url": clean_url,
                "filename": filename,
                "repo": f"{user}/{repo}",
                "branch": branch,
            }
        elif len(parts) >= 1:
            return {
                "kind": "file",
                "url": clean_url,
                "filename": parts[-1],
                "repo": None,
                "branch": None,
            }

    # 2. GitHub Gist: gist.github.com/user/gist_id
    if host in ("gist.github.com", "gist.githubusercontent.com"):
        parts = path.split("/")
        if len(parts) >= 2:
            user, gist_id = parts[0], parts[1]
            raw_gist = f"https://gist.githubusercontent.com/{user}/{gist_id}/raw"
            return {
                "kind": "file",
                "url": raw_gist,
                "filename": f"gist_{gist_id[:8]}.txt",
                "repo": f"gist/{user}/{gist_id}",
                "branch": None,
            }

    # 3. Standard github.com
    if host == "github.com":
        parts = path.split("/")
        if len(parts) >= 2:
            user = parts[0]
            repo = parts[1].removesuffix(".git")
            repo_full = f"{user}/{repo}"

            # Direct file (blob or raw): /user/repo/blob/{branch}/{path} or /user/repo/raw/{branch}/{path}
            if len(parts) >= 5 and parts[2] in ("blob", "raw"):
                branch = parts[3]
                filepath = "/".join(parts[4:])
                filename = parts[-1]
                raw_file_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{filepath}"
                return {
                    "kind": "file",
                    "url": raw_file_url,
                    "filename": filename,
                    "repo": repo_full,
                    "branch": branch,
                }

            # Tree branch / folder: /user/repo/tree/{branch}/...
            if len(parts) >= 4 and parts[2] == "tree":
                branch = parts[3]
                zip_url = f"https://github.com/{user}/{repo}/archive/refs/heads/{branch}.zip"
                return {
                    "kind": "repo",
                    "url": zip_url,
                    "filename": f"{repo}-{branch}.zip",
                    "repo": repo_full,
                    "branch": branch,
                }

            # Whole repository: /user/repo
            if len(parts) == 2:
                zip_url = f"https://github.com/{user}/{repo}/archive/HEAD.zip"
                return {
                    "kind": "repo",
                    "url": zip_url,
                    "filename": f"{repo}.zip",
                    "repo": repo_full,
                    "branch": None,
                }

    return None


def _github_url_to_raw(url: str) -> tuple[str | None, str | None]:
    """Compatibility wrapper: returns (raw_url, filename) if URL points to a single file."""
    parsed = _parse_github_url(url)
    if parsed and parsed.get("kind") == "file":
        return parsed["url"], parsed["filename"]
    return None, None


@app.post("/audit/github")
async def audit_github(request: Request, github_url: str = Form(...)):
    """Fetch a GitHub repository or direct file and run an AI audit."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    github_url = (github_url or "").strip()
    if not github_url:
        raise HTTPException(status_code=400, detail="GitHub URL is required.")

    parsed = _parse_github_url(github_url)
    if not parsed:
        raise HTTPException(
            status_code=400,
            detail=(
                "Could not parse GitHub URL. Supported formats:\n"
                "• Full repository: https://github.com/owner/repository\n"
                "• Branch: https://github.com/owner/repository/tree/main\n"
                "• Direct file: https://github.com/owner/repository/blob/main/app.py\n"
                "• Raw URL: https://raw.githubusercontent.com/owner/repository/main/app.py\n"
                "• Gist: https://gist.github.com/owner/gist_id"
            )
        )

    # ── Case A: Whole repository or branch ──────────────────────────────
    if parsed["kind"] == "repo":
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                headers = {
                    "User-Agent": "AST-Sentinel/1.0",
                    "Accept": "application/vnd.github.v3+json, application/zip",
                }
                resp = await client.get(parsed["url"], headers=headers)
                resp.raise_for_status()
                zip_bytes = resp.content
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail=f"Downloading repository '{parsed['repo']}' timed out. Please try again or use a direct file URL."
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Repository '{parsed['repo']}' not found or is private. Please ensure the repository is public."
                )
            raise HTTPException(
                status_code=400,
                detail=f"Could not download repository archive: HTTP {e.response.status_code}"
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to fetch repository from GitHub: {str(e)}")

        if len(zip_bytes) > 25 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Repository archive exceeds maximum 25MB limit.")

        try:
            extracted = extract_zip(zip_bytes)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if not extracted:
            raise HTTPException(
                status_code=400,
                detail=f"No valid source code files found in repository '{parsed['repo']}'."
            )

        all_findings, all_topics = [], set()
        total_scores = {"security": [], "accessibility": [], "performance": [], "maintainability": [], "overall": []}
        file_results = []

        for ef in extracted:
            try:
                result = await audit_code(ef["content"], filename=ef["filename"], language_hint=ef["language"])
                file_results.append({
                    "filename": ef["filename"],
                    "language": result.get("language", ef["language"]),
                    "summary": result.get("summary", ""),
                    "scores": result.get("scores", {}),
                    "findings_count": len(result.get("findings", [])),
                })
                for finding in result.get("findings", []):
                    finding["source_file"] = ef["filename"]
                    all_findings.append(finding)
                for topic in result.get("topics_detected", []):
                    all_topics.add(topic)
                for key in total_scores:
                    if key in result.get("scores", {}):
                        total_scores[key].append(result["scores"][key])
            except Exception:
                continue

        avg_scores = {k: round(sum(v) / len(v)) if v else 50 for k, v in total_scores.items()}
        languages = [ef["language"] for ef in extracted]
        most_common_lang = max(set(languages), key=languages.count) if languages else "unknown"

        repo_name = parsed["repo"] or "github-repo"
        aggregate_result = {
            "language": most_common_lang,
            "summary": f"GitHub repository audit of {repo_name}: analyzed {len(extracted)} source files.",
            "findings": all_findings,
            "scores": avg_scores,
            "topics_detected": list(all_topics),
            "complexity_level": "advanced" if len(extracted) > 5 else "intermediate",
            "file_results": file_results,
            "github_url": github_url,
            "repo_name": repo_name,
        }

        audit_id = str(uuid.uuid4())
        audit_data = {
            "id": audit_id,
            "user_id": user["id"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "language": most_common_lang,
            "filename": f"github:{repo_name}",
            "source_type": "github-repo",
            "code_length": sum(ef["size"] for ef in extracted),
            "scores": avg_scores,
            "complexity_level": aggregate_result["complexity_level"],
            "summary": aggregate_result["summary"],
            "findings": all_findings,
            "topics_detected": list(all_topics),
            "raw_response": json.dumps(aggregate_result),
        }
        db = await get_db()
        try:
            await save_audit(db, audit_data)
        finally:
            await db.close()

        return RedirectResponse(url=f"/audit/{audit_id}", status_code=303)

    # ── Case B: Single file from GitHub ─────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            headers = {"Accept": "text/plain", "User-Agent": "AST-Sentinel/1.0"}
            resp = await client.get(parsed["url"], headers=headers)
            resp.raise_for_status()
            code = resp.text
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="GitHub request timed out. Please try again.")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="GitHub file not found or is private. Check the URL and ensure the repo is public.")
        raise HTTPException(status_code=400, detail=f"Could not fetch file from GitHub: HTTP {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch from GitHub: {str(e)}")

    if not code.strip():
        raise HTTPException(status_code=400, detail="The fetched file is empty.")
    if len(code) > 100_000:
        raise HTTPException(status_code=400, detail="File exceeds 100,000 character limit.")

    detected_filename = parsed.get("filename")
    language = detect_language(filename=detected_filename, code=code)

    try:
        result = await audit_code(code, filename=detected_filename, language_hint=language)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "user_id": user["id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "language": result.get("language", language),
        "filename": detected_filename or github_url,
        "source_type": "github",
        "code_length": len(code),
        "scores": result.get("scores", {}),
        "complexity_level": result.get("complexity_level", "intermediate"),
        "summary": result.get("summary", ""),
        "findings": result.get("findings", []),
        "topics_detected": result.get("topics_detected", []),
        "raw_response": json.dumps({**result, "github_url": github_url}),
    }

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
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

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
        result = await audit_code_with_requirements(
            code, requirements, filename=filename, language_hint=language
        )
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Create audit record
    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "user_id": user["id"],
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
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

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
        result = await audit_code_with_requirements(code, requirements, filename=file.filename, language_hint=language)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "user_id": user["id"],
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
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

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
            result = await audit_code_with_requirements(
                ef["content"], requirements,
                filename=ef["filename"], language_hint=ef["language"]
            )

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
        "user_id": user["id"],
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
    """Fetch a GitHub repository or file and run a standards audit."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    github_url = (github_url or "").strip()
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

    parsed = _parse_github_url(github_url)
    if not parsed:
        raise HTTPException(
            status_code=400,
            detail=(
                "Could not parse GitHub URL. Supported formats:\n"
                "• Full repository: https://github.com/owner/repository\n"
                "• Branch: https://github.com/owner/repository/tree/main\n"
                "• Direct file: https://github.com/owner/repository/blob/main/app.py\n"
                "• Raw URL: https://raw.githubusercontent.com/owner/repository/main/app.py\n"
                "• Gist: https://gist.github.com/owner/gist_id"
            )
        )

    # ── Case A: Whole repository or branch ──────────────────────────────
    if parsed["kind"] == "repo":
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                headers = {
                    "User-Agent": "AST-Sentinel/1.0",
                    "Accept": "application/vnd.github.v3+json, application/zip",
                }
                resp = await client.get(parsed["url"], headers=headers)
                resp.raise_for_status()
                zip_bytes = resp.content
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail=f"Downloading repository '{parsed['repo']}' timed out. Please try again or use a direct file URL."
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Repository '{parsed['repo']}' not found or is private. Please ensure the repository is public."
                )
            raise HTTPException(
                status_code=400,
                detail=f"Could not download repository archive: HTTP {e.response.status_code}"
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to fetch repository from GitHub: {str(e)}")

        if len(zip_bytes) > 25 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Repository archive exceeds maximum 25MB limit.")

        try:
            extracted = extract_zip(zip_bytes)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if not extracted:
            raise HTTPException(
                status_code=400,
                detail=f"No valid source code files found in repository '{parsed['repo']}'."
            )

        # Audit each file against the requirements
        all_findings, all_topics = [], set()
        total_scores = {"security": [], "accessibility": [], "performance": [], "maintainability": [], "overall": [], "standards": []}
        all_checklists, file_results, errors = [], [], []

        for ef in extracted:
            try:
                result = await audit_code_with_requirements(
                    ef["content"], requirements,
                    filename=ef["filename"], language_hint=ef["language"]
                )

                file_results.append({
                    "filename": ef["filename"],
                    "language": result.get("language", ef["language"]),
                    "summary": result.get("summary", ""),
                    "scores": result.get("scores", {}),
                    "findings_count": len(result.get("findings", [])),
                    "checklist_pass": sum(1 for c in result.get("requirements_checklist", []) if c.get("status") == "pass"),
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

                for item in result.get("requirements_checklist", []):
                    all_checklists.append(item)

            except Exception as e:
                errors.append({"filename": ef["filename"], "error": str(e)})

        avg_scores = {k: round(sum(v) / len(v)) if v else 50 for k, v in total_scores.items()}

        # Deduplicate checklist — worst status wins
        STATUS_RANK = {"pass": 0, "partial": 1, "fail": 2}
        deduped: dict[str, dict] = {}
        for item in all_checklists:
            key = item.get("requirement", "")
            if key not in deduped or STATUS_RANK.get(item.get("status", ""), 0) > STATUS_RANK.get(deduped[key].get("status", ""), 0):
                deduped[key] = item
        merged_checklist = list(deduped.values())

        languages = [ef["language"] for ef in extracted]
        most_common_lang = max(set(languages), key=languages.count) if languages else "unknown"

        repo_name = parsed["repo"] or "github-repo"
        aggregate_result = {
            "language": most_common_lang,
            "summary": f"GitHub repository standards audit of {repo_name}: analyzed {len(extracted)} source files.",
            "findings": all_findings,
            "scores": avg_scores,
            "topics_detected": list(all_topics),
            "complexity_level": "advanced" if len(extracted) > 5 else "intermediate",
            "requirements_checklist": merged_checklist,
            "standards_summary": f"Audited {len(extracted)} files from {repo_name} against your requirements. Average compliance: {avg_scores.get('standards', 0)}/100.",
            "file_results": file_results,
            "errors": errors,
            "github_url": github_url,
            "repo_name": repo_name,
        }

        audit_id = str(uuid.uuid4())
        audit_data = {
            "id": audit_id,
            "user_id": user["id"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "language": most_common_lang,
            "filename": f"github:{repo_name}",
            "source_type": "standards-github-repo",
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

    # ── Case B: Single file from GitHub ─────────────────────────────────
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            headers = {"Accept": "text/plain", "User-Agent": "AST-Sentinel/1.0"}
            resp = await client.get(parsed["url"], headers=headers)
            resp.raise_for_status()
            code = resp.text
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="GitHub request timed out. Please try again.")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise HTTPException(status_code=404, detail="GitHub file not found or is private. Check the URL and ensure the repo is public.")
        raise HTTPException(status_code=400, detail=f"Could not fetch file from GitHub: HTTP {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch from GitHub: {str(e)}")

    if not code.strip():
        raise HTTPException(status_code=400, detail="The fetched file is empty.")
    if len(code) > 100_000:
        raise HTTPException(status_code=400, detail="File exceeds 100,000 character limit.")

    detected_filename = parsed.get("filename")
    language = detect_language(filename=detected_filename, code=code)

    try:
        result = await audit_code_with_requirements(code, requirements, filename=detected_filename, language_hint=language)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e))

    audit_id = str(uuid.uuid4())
    audit_data = {
        "id": audit_id,
        "user_id": user["id"],
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



@app.get("/api/analytics")
async def api_analytics(request: Request):
    """JSON API for analytics data (consumed by Chart.js), scoped to current user."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    db = await get_db()
    try:
        data = await get_full_analytics(db, user_id=user["id"])
    finally:
        await db.close()
    return JSONResponse(content=data)

@app.get("/api/audit/{audit_id}/export")
async def export_audit(request: Request, audit_id: str):
    """Export audit results as JSON."""
    user = await get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    db = await get_db()
    try:
        audit = await get_audit(db, audit_id)
    finally:
        await db.close()

    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    if audit.get("user_id") and audit.get("user_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    return JSONResponse(content=audit)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)


