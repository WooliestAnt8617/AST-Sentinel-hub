# AST-Sentinel

**Deterministic Static Source Code Security & Vulnerability Audit Engine**

A full-stack SAST engine that parses Python source into AST nodes, traverses them via a modular Visitor Pattern rule registry, computes composite risk scores, and exposes results through an async FastAPI API with structured JSON/HTML reporting.

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

### CLI Scan
```bash
# Scan a file or directory
ast-sentinel scan ./my_project/

# With JSON + HTML report output
ast-sentinel scan ./my_project/ --json report.json --html report.html -v
```

### API Server
```bash
# Start the FastAPI server
ast-sentinel serve --host 0.0.0.0 --port 8000

# Then visit http://localhost:8000/docs for Swagger UI
```

## Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| SEC-001 | Hardcoded Secrets | HIGH/CRITICAL | Detects passwords, API keys, tokens assigned as string literals |
| SEC-002 | Code Injection | CRITICAL | Flags `eval()`, `exec()`, `subprocess` with `shell=True` |
| SEC-003 | SQL Injection | CRITICAL | Catches dynamic SQL via f-strings, `%` formatting, `.format()` |
| SEC-004 | Insecure Cryptography | HIGH | Identifies MD5, SHA-1, non-cryptographic PRNGs |
| SEC-005 | Unsafe Deserialization | HIGH | Detects `pickle.loads()`, `yaml.load()` without SafeLoader |
| SEC-006 | Exception Handling | MEDIUM | Bare `except:`, overly broad catches, empty except bodies |

## Running Tests

```bash
pytest tests/ -v
```

## License

MIT
