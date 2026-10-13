# AST-Sentinel Hub

> **Static Source Code Security Audit Engine & AI-Powered Web Auditor**

AST-Sentinel is a dual-interface security analysis platform for Python and multi-language projects. It provides two complementary ways to audit your code:

```
  +-------------------------------------+   +------------------------------------+
  |      AST-Sentinel CLI               |   |   AST-Sentinel: Code Auditor       |
  |  Standalone .exe or pip package     |   |   AI-powered web platform          |
  |  Deterministic · AST rules · CI/CD  |   |   Deep analysis · History · Web UI |
  +-------------------------------------+   +------------------------------------+
```

---

## What Is AST-Sentinel?

**AST-Sentinel** is a static application security testing (SAST) and code intelligence ecosystem consisting of two integrated parts:

1. **AST-Sentinel CLI (Core SAST Engine)**: A deterministic, rule-based static analysis engine for Python. It parses source code into Abstract Syntax Trees (`ast`), applies a modular Visitor-Pattern security registry, detects vulnerabilities (secrets, injections, unsafe deserialization, insecure crypto, etc.), and outputs formatted terminal tables or JSON/HTML reports. It operates entirely offline with zero runtime dependencies.
2. **AST-Sentinel Code Auditor (Web Interface)**: The companion web application located in `code-auditor/`. It provides a modern browser UI powered by FastAPI and Google Gemini. It handles multi-language auditing, ZIP uploads, GitHub links, standards compliance audits (OWASP, PEP 8, SOLID), user authentication, audit history, analytics dashboards, and direct downloads of the standalone CLI executable.

---

## Two Ways to Audit Your Code

| Feature | 💻 AST-Sentinel CLI | 🌐 Code Auditor (Web) |
|---|---|---|
| **Primary Interface** | Command prompt / Terminal / CI/CD | Browser (FastAPI + Modern Web UI) |
| **Analysis Engine** | Deterministic Python AST rules | Google Gemini AI + AST heuristics |
| **Network Required** | **No** (100% offline) | Yes (Gemini API & local server) |
| **Language Support** | Python | Python, JS, TS, Go, Rust, Java, C++, PHP, etc. |
| **Zero Installation** | Standalone `ast-sentinel.exe` (run directly) | Browser UI (open `http://localhost:8000`) |
| **Export Formats** | Terminal colors, JSON, standalone HTML | Browser view, JSON export, HTML |
| **Multi-file / Project** | Recursive directory scanning | ZIP archive upload or multi-file tree |
| **Standards Checks** | Rule-based (SEC-001 through SEC-006) | Framework checks (OWASP Top 10, PEP 8, SOLID) |
| **Audit History & Analytics** | Standalone report files | Persistent SQLite DB with user dashboard |

---

## 💻 1. AST-Sentinel CLI — Usage & Help Menu

The CLI can be run either as a standalone Windows binary (`ast-sentinel.exe`) or installed from source via Python.

### Getting the CLI

#### Option A: Download the Standalone Executable (Windows)
Download `ast-sentinel.exe` directly from the **Code Auditor** web interface at `http://localhost:8000/download`.  
No Python installation or dependencies required. Simply open `cmd` or `powershell` and run:
```cmd
ast-sentinel.exe --help
```

#### Option B: Install from Source (Cross-Platform)
Requires Python >= 3.10:
```bash
git clone https://github.com/WooliestAnt8617/AST-Sentinel-hub.git
cd AST-Sentinel-hub
pip install -e ".[dev]"
```

---

### CLI Help Menu & Command Reference

AST-Sentinel features an interactive help menu and built-in usage documentation accessible directly from your terminal:

```
ast-sentinel --help
ast-sentinel help
ast-sentinel help scan
ast-sentinel help serve
```

#### Global Commands

```
usage: ast-sentinel [-h] COMMAND ...

positional arguments:
  COMMAND
    scan          Scan a Python file or directory for security vulnerabilities
    serve         Start the local AST-Sentinel FastAPI REST API server
    help          Show detailed help and usage manual for commands

options:
  -h, --help      Show help message and exit
```

#### `scan` Command

```
usage: ast-sentinel scan [-h] [--json FILE] [--html FILE] [-v] target

positional arguments:
  target          Path to a .py file or directory to scan (scanned recursively)

options:
  -h, --help      Show help message and exit
  --json FILE     Write findings to FILE as structured JSON (e.g. report.json)
  --html FILE     Write a self-contained HTML report to FILE (e.g. report.html)
  -v, --verbose   Show full remediation advice and source code snippets
```

#### `serve` Command

```
usage: ast-sentinel serve [-h] [--host HOST] [--port PORT]

options:
  --host HOST     Host/IP to bind the server to (default: 127.0.0.1)
  --port PORT     TCP port to listen on (default: 8000)
```

---

### CLI Examples

```cmd
:: 1. Scan a single Python file
ast-sentinel scan myfile.py

:: 2. Scan an entire directory recursively with verbose explanations
ast-sentinel scan ./src/ -v

:: 3. Export structured JSON findings for CI/CD pipelines
ast-sentinel scan ./src/ --json findings.json

:: 4. Export self-contained HTML security report
ast-sentinel scan ./src/ --html security-report.html

:: 5. Launch the local AST-Sentinel REST API server (Swagger UI at /docs)
ast-sentinel serve --port 8080
```

---

## 🌐 2. AST-Sentinel Code Auditor (Web App) — Quick Start

The **Code Auditor** provides a rich web dashboard for interactive audits, project uploads, and team reporting.

```bash
cd code-auditor
pip install -r requirements.txt
cp .env.example .env   # Configure GEMINI_API_KEY
python main.py
```
Open **`http://127.0.0.1:8000`** in your browser.

### Key Features of Code Auditor
- **Instant Snippet Auditing**: Paste any code snippet across 15+ languages for automated review.
- **ZIP Archive & Project Audits**: Upload a `.zip` archive of your codebase for whole-project analysis and file trees.
- **GitHub URL Audits**: Point directly to raw GitHub files or gists.
- **Standards & Compliance Checks**: Run targeted audits against OWASP Top 10, PEP 8, and SOLID design principles.
- **Download Hub (`/download`)**: Built-in distribution page to download the standalone `ast-sentinel.exe` binary.
- **Audit History & Accounts**: Secure session authentication, past audit records, and aggregate analytics.

---

## Built-In Security Rules (CLI Engine)

| Rule ID | Name | Severity | Description |
|---|---|---|---|
| **SEC-001** | Hardcoded Secrets | `CRITICAL` / `HIGH` | Detects passwords, API keys, tokens, and secrets hardcoded in strings. |
| **SEC-002** | Code Injection | `CRITICAL` | Flags `eval()`, `exec()`, `input()`, and `subprocess` executions with `shell=True`. |
| **SEC-003** | SQL Injection | `CRITICAL` | Detects dynamic SQL string construction via f-strings, `%`, or `.format()`. |
| **SEC-004** | Insecure Cryptography | `HIGH` | Flags weak cryptographic algorithms (MD5, SHA-1, DES) and pseudo-random numbers (`random`). |
| **SEC-005** | Unsafe Deserialization | `HIGH` | Flags `pickle.loads()`, `yaml.load()` without SafeLoader, and `marshal.loads()`. |
| **SEC-006** | Exception Handling | `MEDIUM` | Identifies bare `except:`, broad `except Exception:` with `pass`, and suppressed errors. |

---

## Project Structure

```
AST-Sentinel-hub/
├── ast_sentinel/              # Deterministic CLI & Core SAST Engine
│   ├── core/
│   │   ├── parser.py          # AST parser
│   │   ├── registry.py        # Rule registry & visitor dispatcher
│   │   ├── scanner.py         # Scanner orchestrator & file walker
│   │   └── visitor.py         # AST visitor base classes
│   ├── rules/                 # Security rule implementations (SEC-001 to SEC-006)
│   ├── metrics/               # Risk score calculation
│   ├── reporting/             # Terminal, JSON, and HTML report generators
│   ├── api/                   # REST API routes
│   └── main.py                # CLI entry point, argparse help menu & server
│
├── code-auditor/              # AST-Sentinel Web Platform
│   ├── main.py                # FastAPI web server & download endpoints
│   ├── database.py            # SQLite database with aiosqlite
│   ├── services/              # Gemini auditor, analytics, auth, file handler
│   ├── templates/             # Jinja2 templates (dashboard, download, audit)
│   ├── static/                # CSS, JavaScript, and compiled binary distribution
│   │   └── bin/               # Pre-built ast-sentinel.exe
│   └── requirements.txt       # Web platform dependencies
│
├── scripts/
│   └── build_cli.py           # PyInstaller build automation script
│
├── tests/                     # Unit and integration test suite
└── pyproject.toml             # Python package configuration
```

---

## Building the CLI Standalone Binary

You can compile the CLI into a single-file executable using the provided build script:

```bash
pip install pyinstaller
python scripts/build_cli.py
```

The script builds `dist/ast-sentinel.exe` and copies it into `code-auditor/static/bin/ast-sentinel.exe` so the web app can serve it directly.

---

## Running Tests

```bash
pytest tests/ -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
