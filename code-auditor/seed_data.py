"""
Seed script to populate sample audit data into SQLite.
Run this script to immediately see populated charts and metrics on the Analytics Dashboard!
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
# pyrefly: ignore [missing-import]
from database import init_db, get_db, save_audit

SAMPLE_AUDITS = [
    {
        "language": "python",
        "filename": "auth_service.py",
        "source_type": "paste",
        "code_length": 1420,
        "scores": {"security": 65, "accessibility": 88, "performance": 80, "maintainability": 75, "overall": 72},
        "complexity_level": "intermediate",
        "summary": "Authentication service handling user JWT token generation and password hashing. Contains hardcoded secret fallback and raw SQL string formatting.",
        "findings": [
            {
                "severity": "critical",
                "category": "security",
                "title": "Hardcoded Secret Key Fallback",
                "description": "The secret key falls back to a default hardcoded string 'dev-secret-key-123' if the environment variable is missing, allowing token forgery in misconfigured environments.",
                "line_range": [14, 16],
                "suggestion": "Raise a ConfigurationError on startup if GEMINI_API_KEY or JWT_SECRET is missing instead of defaulting to a static string.",
                "code_snippet": "secret = os.getenv('JWT_SECRET')\nif not secret:\n    raise RuntimeError('JWT_SECRET environment variable is required')"
            },
            {
                "severity": "high",
                "category": "security",
                "title": "Potential SQL Injection",
                "description": "User input is directly formatted into SQL query string instead of using parameterized bindings.",
                "line_range": [42, 45],
                "suggestion": "Use parameterized queries with placeholers (?, %s, etc.).",
                "code_snippet": "cursor.execute('SELECT * FROM users WHERE username = ?', (username,))"
            },
            {
                "severity": "medium",
                "category": "error-handling",
                "title": "Bare Exception Clause",
                "description": "Catching generic Exception without logging or re-raising swallows database connection errors silently.",
                "line_range": [78, 82],
                "suggestion": "Catch specific exception types like sqlite3.Error or DBAPIError.",
                "code_snippet": "except sqlite3.DatabaseError as err:\n    logger.error('Database failure: %s', err)\n    raise"
            }
        ],
        "topics_detected": ["authentication", "SQL queries", "JWT", "password hashing"]
    },
    {
        "language": "javascript",
        "filename": "component.jsx",
        "source_type": "paste",
        "code_length": 850,
        "scores": {"security": 90, "accessibility": 45, "performance": 85, "maintainability": 80, "overall": 75},
        "complexity_level": "beginner",
        "summary": "React navigation component rendering dynamic user menus and action items.",
        "findings": [
            {
                "severity": "high",
                "category": "accessibility",
                "title": "Missing ARIA Labels on Icon Buttons",
                "description": "Clickable icon buttons lack aria-label attributes, making them unnavigable for screen reader users.",
                "line_range": [22, 28],
                "suggestion": "Add aria-label attributes describing the action of each icon button.",
                "code_snippet": "<button aria-label=\"Open User Settings\" onClick={openSettings}>\n  <SettingsIcon />\n</button>"
            },
            {
                "severity": "low",
                "category": "best-practice",
                "title": "Missing Key Prop in Iterated List",
                "description": "Array mapping produces elements without a unique 'key' prop.",
                "line_range": [35, 40],
                "suggestion": "Pass item.id as the key prop to avoid unnecessary DOM re-renders.",
                "code_snippet": "{items.map(item => <ListItem key={item.id} data={item} />)}"
            }
        ],
        "topics_detected": ["UI rendering", "React components", "DOM events"]
    },
    {
        "language": "go",
        "filename": "worker_pool.go",
        "source_type": "zip",
        "code_length": 3200,
        "scores": {"security": 95, "accessibility": 90, "performance": 92, "maintainability": 88, "overall": 91},
        "complexity_level": "advanced",
        "summary": "Concurrent worker pool manager utilizing goroutines and channels for background job processing.",
        "findings": [
            {
                "severity": "medium",
                "category": "performance",
                "title": "Unbuffered Channel May Cause Deadlock",
                "description": "Job submission channel is unbuffered, which can block the main loop if workers are busy.",
                "line_range": [50, 55],
                "suggestion": "Use a buffered channel sized appropriately for peak concurrency queue length.",
                "code_snippet": "jobs := make(chan Job, 100)"
            },
            {
                "severity": "info",
                "category": "maintainability",
                "title": "Exported Symbol Lacks Docstring",
                "description": "Public function ProcessTask is exported without a top-level documentation comment.",
                "line_range": [12, 14],
                "suggestion": "Add godoc comment starting with function name.",
                "code_snippet": "// ProcessTask executes a single job unit asynchronously.\nfunc ProcessTask(j Job) error {"
            }
        ],
        "topics_detected": ["concurrency", "channels", "worker pools", "background processing"]
    },
    {
        "language": "typescript",
        "filename": "api_client.ts",
        "source_type": "paste",
        "code_length": 1100,
        "scores": {"security": 85, "accessibility": 95, "performance": 78, "maintainability": 90, "overall": 87},
        "complexity_level": "intermediate",
        "summary": "Type-safe HTTP client wrapper around Fetch API with automatic retries and response transformation.",
        "findings": [
            {
                "severity": "low",
                "category": "error-handling",
                "title": "Unhandled Rejection on Timeout",
                "description": "AbortController timeout signal rejection isn't properly caught before returning error response.",
                "line_range": [30, 34],
                "suggestion": "Wrap fetch call in try/catch block specifically checking for AbortError.",
                "code_snippet": "try {\n  return await fetch(url, { signal });\n} catch (err) {\n  if (err.name === 'AbortError') throw new TimeoutError();\n  throw err;\n}"
            }
        ],
        "topics_detected": ["networking", "Fetch API", "async/await", "TypeScript types"]
    },
    {
        "language": "python",
        "filename": "data_processor.py",
        "source_type": "zip",
        "code_length": 2400,
        "scores": {"security": 70, "accessibility": 85, "performance": 55, "maintainability": 68, "overall": 69},
        "complexity_level": "intermediate",
        "summary": "ETL script parsing large JSON payloads and writing records to disk.",
        "findings": [
            {
                "severity": "high",
                "category": "performance",
                "title": "O(N^2) Loop Nesting on Data Matching",
                "description": "Nested loops checking record existence against a list causes significant CPU bottleneck on large datasets.",
                "line_range": [64, 75],
                "suggestion": "Convert list lookup to set hashing for O(1) membership checks.",
                "code_snippet": "existing_ids = set(record['id'] for record in db_records)\nfor item in incoming:\n    if item['id'] not in existing_ids: ..."
            },
            {
                "severity": "medium",
                "category": "security",
                "title": "Insecure Temporary File Creation",
                "description": "Uses standard open('/tmp/temp.txt') instead of tempfile.NamedTemporaryFile with secure permissions.",
                "line_range": [112, 115],
                "suggestion": "Use Python's built-in tempfile module.",
                "code_snippet": "import tempfile\nwith tempfile.NamedTemporaryFile(mode='w+', delete=True) as tmp:\n    tmp.write(data)"
            }
        ],
        "topics_detected": ["file I/O", "ETL", "JSON processing", "data matching"]
    }
]


async def seed():
    print("Initializing database...")
    await init_db()
    db = await get_db()
    
    try:
        now = datetime.now(timezone.utc)
        for i, audit_def in enumerate(SAMPLE_AUDITS):
            created_at = (now - timedelta(days=len(SAMPLE_AUDITS) - i - 1, hours=i * 2)).isoformat()
            audit_id = str(uuid.uuid4())
            
            audit_data = {
                "id": audit_id,
                "created_at": created_at,
                "language": audit_def["language"],
                "filename": audit_def["filename"],
                "source_type": audit_def["source_type"],
                "code_length": audit_def["code_length"],
                "scores": audit_def["scores"],
                "complexity_level": audit_def["complexity_level"],
                "summary": audit_def["summary"],
                "findings": audit_def["findings"],
                "topics_detected": audit_def["topics_detected"],
                "raw_response": json.dumps(audit_def),
            }
            
            await save_audit(db, audit_data)
            print(f"  [+] Seeded {audit_def['language']} audit ({audit_def['filename']}) -> ID: {audit_id[:8]}...")
            
        print("\nDatabase seeded successfully!")
    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(seed())
