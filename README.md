# AST-Sentinel Hub

> **Two ways to audit your code — pick the one that fits your workflow.**

```
  +-------------------------------+   +----------------------------------+
  |      CLI Scanner              |   |   CodeIntel  Web App             |
  |  ast-sentinel.exe / pip pkg   |   |  AI-powered · Gemini · Browser   |
  |  Offline · CI/CD · Fast       |   |  Audit history · Analytics       |
  +-------------------------------+   +----------------------------------+
```

---

## What Is AST-Sentinel?

**AST-Sentinel** is a deterministic static application security testing (SAST) engine for Python. It parses source files into Abstract Syntax Trees (AST), walks every node through a modular **Visitor Pattern** rule registry, and produces structured security findings with composite risk scores.

**CodeIntel** is the companion AI-powered web platform. It uses **Google Gemini** as a senior code reviewer to go beyond rule-based detection — covering security, performance, maintainability, accessibility, and standards compliance.

---

## Access Options

| | CLI (AST-Sentinel) | Web App (CodeIntel) |
|---|---|---|
| **Engine** | Deterministic AST rules | Google Gemini AI |
| **Works offline** | Yes | No |
| **CI/CD integration** | Yes | No |
| **Audit history & analytics** | No | Yes |
| **Standards & compliance audit** | No | Yes (OWASP, PEP 8, SOLID) |
| **JSON / HTML report export** | Yes | Yes |
| **ZIP / multi-file scanning** | Yes (directory) | Yes (zip upload) |
| **No install required** | No | Yes (browser) |

---

## CLI — Quick Start

### Option A: Download the pre-built Windows executable

Download `ast-sentinel.exe` from the [CodeIntel download page](/download) and run it anywhere — no Python, no pip, no installer.

```cmd
:: Scan a single file
ast-sentinel scan myfile.py

:: Scan a whole project (verbose)
ast-sentinel scan ./src/ --verbose

:: Export JSON + HTML reports
ast-sentinel scan ./src/ --json report.json --html report.html -v

:: Start the local REST API server
ast-sentinel serve --host 0.0.0.0 --port 8000
```

### Option B: Install from source (any OS)

**Requirements:** Python >= 3.10

```bash
git clone https://github.com/WooliestAnt8617/AST-Sentinel-hub.git
cd AST-Sentinel-hub
pip install -e ".[dev]"
```

### CLI Help

```
ast-sentinel --help
ast-sentinel scan --help
ast-sentinel serve --help
```

---

## Web App (CodeIntel) — Quick Start

```bash
cd code-auditor
pip install -r requirements.txt
cp .env.example .env   # Add your Gemini API key
python main.py
# Open http://127.0.0.1:8000
```

### Web App Features

| Feature | Details |
|---|---|
| **Code Paste Audit** | Paste any snippet for instant AI analysis |
| **ZIP Upload** | Upload entire project archives for per-file + aggregate results |
| **GitHub URL Audit** | Point at a raw GitHub file or gist |
| **Standards Audit** | Audit against OWASP, PEP 8, SOLID, custom naming conventions |
| **Analytics Dashboard** | Severity charts, score trends, language breakdown |
| **Audit History** | All past audits stored per-user with full JSON export |
| **Auth** | Email/password sign-up and login with session tokens |

---

## Security Rules (CLI Engine)

| Rule ID | Name | Severity | What It Detects |
|---------|------|----------|-----------------|
| SEC-001 | Hardcoded Secrets | CRITICAL / HIGH | Passwords, API keys, tokens assigned as string literals |
| SEC-002 | Code Injection | CRITICAL | `eval()`, `exec()`, `subprocess` with `shell=True` |
| SEC-003 | SQL Injection | CRITICAL | Dynamic SQL via f-strings, `%` formatting, `.format()` |
| SEC-004 | Insecure Cryptography | HIGH | MD5, SHA-1, non-cryptographic PRNGs (`random`) |
| SEC-005 | Unsafe Deserialization | HIGH | `pickle.loads()`, `yaml.load()` without SafeLoader |
| SEC-006 | Exception Handling | MEDIUM | Bare `except:`, overly broad catches, empty except bodies |

---

## Architecture

```
ast_sentinel/
├── core/
│   ├── parser.py         # AST parsing
│   ├── registry.py       # Rule registry (Visitor Pattern)
│   ├── scanner.py        # ScannerOrchestrator — file/dir traversal
│   └── visitor.py        # Base AST visitor & node dispatch
├── rules/                # One file per security rule
├── metrics/
│   └── risk_score.py     # Composite risk score computation
├── reporting/
│   ├── terminal.py       # Rich terminal output
│   ├── json_report.py    # Structured JSON export
│   └── html_report.py    # Self-contained HTML report
├── api/
│   └── routes.py         # FastAPI REST endpoints
└── main.py               # CLI entry point & FastAPI app factory

code-auditor/
├── main.py               # FastAPI web app (CodeIntel)
├── database.py           # Async SQLite
├── services/
│   ├── auditor.py        # Gemini AI audit logic
│   ├── analytics.py      # Aggregate analytics queries
│   ├── auth.py           # JWT session tokens
│   └── file_handler.py   # ZIP extraction, language detection
└── templates/            # Jinja2 HTML templates

scripts/
└── build_cli.py          # PyInstaller → dist/ast-sentinel.exe
```

---

## Building the CLI Executable

```bash
pip install pyinstaller
python scripts/build_cli.py
# Output: dist/ast-sentinel.exe (also copied to code-auditor/static/bin/)
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| CLI engine | Python 3.10+, `ast` stdlib, `rich` |
| REST API | FastAPI, uvicorn, pydantic |
| Web app | FastAPI, Jinja2, vanilla CSS/JS |
| AI analysis | Google Gemini API |
| Database | SQLite via `aiosqlite` |
| Packaging | PyInstaller (standalone .exe) |

---

## Contributing

1. Fork the repo and create a feature branch
2. Add new rules in `ast_sentinel/rules/` — each is a self-contained visitor class
3. Register the rule in `ast_sentinel/core/registry.py`
4. Add tests in `tests/`
5. Run `ruff check .` and `pytest tests/ -v` before opening a PR

---

## License

MIT
