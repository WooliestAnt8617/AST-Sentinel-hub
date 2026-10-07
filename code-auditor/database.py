"""
Database module — SQLite setup, migrations, and query helpers.
Uses aiosqlite for async database access.
"""

import aiosqlite
import os
from pathlib import Path

DB_DIR = Path(__file__).parent / "data"
DB_PATH = DB_DIR / "auditor.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audits (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    language TEXT NOT NULL,
    filename TEXT,
    source_type TEXT NOT NULL,
    code_length INTEGER,
    score_security INTEGER,
    score_accessibility INTEGER,
    score_performance INTEGER,
    score_maintainability INTEGER,
    score_overall INTEGER,
    score_standards INTEGER,
    complexity_level TEXT,
    summary TEXT,
    audit_requirements TEXT,
    raw_response TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL REFERENCES audits(id),
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    line_start INTEGER,
    line_end INTEGER,
    suggestion TEXT,
    code_snippet TEXT
);

CREATE TABLE IF NOT EXISTS topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id TEXT NOT NULL REFERENCES audits(id),
    topic TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_audit_id ON findings(audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_topics_audit_id ON topics(audit_id);
CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits(created_at);
CREATE INDEX IF NOT EXISTS idx_audits_language ON audits(language);
"""

# Migrations for existing databases
MIGRATIONS = [
    "ALTER TABLE audits ADD COLUMN score_standards INTEGER",
    "ALTER TABLE audits ADD COLUMN audit_requirements TEXT",
]


async def get_db() -> aiosqlite.Connection:
    """Get a database connection with row factory enabled."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(str(DB_PATH))
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")
    return db


async def init_db():
    """Initialize the database schema and run any pending migrations."""
    db = await get_db()
    try:
        await db.executescript(SCHEMA_SQL)
        await db.commit()
        # Run migrations idempotently (ignore errors if column already exists)
        for migration in MIGRATIONS:
            try:
                await db.execute(migration)
                await db.commit()
            except Exception:
                pass  # Column already exists
    finally:
        await db.close()


async def save_audit(db: aiosqlite.Connection, audit_data: dict):
    """Save a complete audit result (audit + findings + topics) to the database."""
    await db.execute(
        """INSERT INTO audits 
           (id, created_at, language, filename, source_type, code_length,
            score_security, score_accessibility, score_performance,
            score_maintainability, score_overall, score_standards,
            complexity_level, summary, audit_requirements, raw_response)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            audit_data["id"],
            audit_data["created_at"],
            audit_data["language"],
            audit_data.get("filename"),
            audit_data["source_type"],
            audit_data.get("code_length", 0),
            audit_data["scores"].get("security", 0),
            audit_data["scores"].get("accessibility", 0),
            audit_data["scores"].get("performance", 0),
            audit_data["scores"].get("maintainability", 0),
            audit_data["scores"].get("overall", 0),
            audit_data["scores"].get("standards"),
            audit_data.get("complexity_level", "intermediate"),
            audit_data.get("summary", ""),
            audit_data.get("audit_requirements"),
            audit_data.get("raw_response", ""),
        ),
    )

    # Save findings
    for finding in audit_data.get("findings", []):
        line_range = finding.get("line_range", [None, None])
        line_start = line_range[0] if line_range and len(line_range) > 0 else None
        line_end = line_range[1] if line_range and len(line_range) > 1 else None
        await db.execute(
            """INSERT INTO findings 
               (audit_id, severity, category, title, description, line_start, line_end, suggestion, code_snippet)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                audit_data["id"],
                finding.get("severity", "info"),
                finding.get("category", "best-practice"),
                finding.get("title", "Untitled Finding"),
                finding.get("description", ""),
                line_start,
                line_end,
                finding.get("suggestion", ""),
                finding.get("code_snippet", ""),
            ),
        )

    # Save topics
    for topic in audit_data.get("topics_detected", []):
        await db.execute(
            "INSERT INTO topics (audit_id, topic) VALUES (?, ?)",
            (audit_data["id"], topic),
        )

    await db.commit()


async def get_audit(db: aiosqlite.Connection, audit_id: str) -> dict | None:
    """Retrieve a full audit by ID, including findings and topics."""
    cursor = await db.execute("SELECT * FROM audits WHERE id = ?", (audit_id,))
    row = await cursor.fetchone()
    if not row:
        return None

    audit = dict(row)

    # Get findings
    cursor = await db.execute(
        "SELECT * FROM findings WHERE audit_id = ? ORDER BY CASE severity "
        "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
        "WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END",
        (audit_id,),
    )
    findings = await cursor.fetchall()
    audit["findings"] = [dict(f) for f in findings]

    # Get topics
    cursor = await db.execute(
        "SELECT topic FROM topics WHERE audit_id = ?", (audit_id,)
    )
    topics = await cursor.fetchall()
    audit["topics"] = [t["topic"] for t in topics]

    return audit


async def get_all_audits_summary(db: aiosqlite.Connection) -> list[dict]:
    """Get a summary list of all audits (for listing / navigation)."""
    cursor = await db.execute(
        "SELECT id, created_at, language, filename, source_type, score_overall, summary "
        "FROM audits ORDER BY created_at DESC LIMIT 100"
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]
