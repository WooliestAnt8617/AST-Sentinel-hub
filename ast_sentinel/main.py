"""
AST-Sentinel: Deterministic Static Source Code Security & Vulnerability Audit Engine

Entry point for both the FastAPI server and CLI scanning.
"""
import argparse
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ast_sentinel.api.routes import router
from ast_sentinel.core.registry import get_registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle handler."""
    registry = get_registry()
    rules = registry.get_all_rules()
    print(f"[AST-Sentinel] Loaded {len(rules)} security rules: {', '.join(rules.keys())}")
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="AST-Sentinel",
        description="Deterministic Static Source Code Security & Vulnerability Audit Engine",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    return app


app = create_app()


def run_cli(args: argparse.Namespace):
    """Run a scan from the command line and print results to terminal."""
    from ast_sentinel.core.scanner import ScannerOrchestrator
    from ast_sentinel.metrics.risk_score import compute_risk_score
    from ast_sentinel.reporting.html_report import generate_html_report
    from ast_sentinel.reporting.json_report import generate_json_report
    from ast_sentinel.reporting.terminal import print_terminal_report

    scanner = ScannerOrchestrator()
    target = Path(args.target)

    if not target.exists():
        print(f"Error: path '{target}' not found.", file=sys.stderr)
        sys.exit(1)

    # scan_directory already handles both single files and directories
    result = scanner.scan_directory(str(target), recursive=True)

    # Compute risk score
    result.risk_score = compute_risk_score(result)

    # Terminal output
    print_terminal_report(result, verbose=args.verbose)

    # Optional JSON output
    if args.json:
        output_path = Path(args.json)
        generate_json_report(result, output_path)
        print(f"\nJSON report saved to: {output_path}")

    # Optional HTML output
    if args.html:
        output_path = Path(args.html)
        generate_html_report(result, output_path)
        print(f"\nHTML report saved to: {output_path}")


def run():
    """Main entry point — dispatches to CLI scan or API server."""
    parser = argparse.ArgumentParser(
        prog="ast-sentinel",
        description=(
            "AST-Sentinel — Deterministic Static Source Code Security & Vulnerability Audit Engine\n\n"
            "Parses Python source files into AST nodes and traverses them with a modular rule\n"
            "registry to detect security vulnerabilities, compute risk scores, and produce\n"
            "structured JSON or HTML reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ast-sentinel scan myfile.py\n"
            "  ast-sentinel scan ./src/ --verbose\n"
            "  ast-sentinel scan ./src/ --json report.json --html report.html\n"
            "  ast-sentinel serve --host 0.0.0.0 --port 8080\n"
            "\n"
            "Security rules applied:\n"
            "  SEC-001  Hardcoded Secrets     (CRITICAL/HIGH)\n"
            "  SEC-002  Code Injection        (CRITICAL)      eval/exec/shell=True\n"
            "  SEC-003  SQL Injection         (CRITICAL)      dynamic query construction\n"
            "  SEC-004  Insecure Cryptography (HIGH)          MD5, SHA-1, weak PRNGs\n"
            "  SEC-005  Unsafe Deserialization(HIGH)          pickle.loads, yaml.load\n"
            "  SEC-006  Exception Handling    (MEDIUM)        bare except, swallowed errors\n"
            "\n"
            "For the AI-powered web interface (Code Intelligence Platform), visit:\n"
            "  https://github.com/WooliestAnt8617/AST-Sentinel-hub\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # --- 'scan' subcommand ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Python file or directory for security vulnerabilities",
        description=(
            "Recursively scan a Python source file or directory.\n\n"
            "The scanner parses each .py file into an Abstract Syntax Tree (AST),\n"
            "applies all registered security rules, computes a composite risk score,\n"
            "and prints a colour-coded report to the terminal.\n\n"
            "Optionally export the findings as a JSON data file or a self-contained\n"
            "HTML report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ast-sentinel scan app.py\n"
            "  ast-sentinel scan ./src/ -v\n"
            "  ast-sentinel scan ./project/ --json findings.json\n"
            "  ast-sentinel scan ./project/ --json out.json --html out.html -v\n"
        ),
    )
    scan_parser.add_argument(
        "target",
        help="Path to a .py file or a directory to scan (scanned recursively)",
    )
    scan_parser.add_argument(
        "--json",
        metavar="FILE",
        help="Write findings to FILE as structured JSON (e.g. report.json)",
        default=None,
    )
    scan_parser.add_argument(
        "--html",
        metavar="FILE",
        help="Write a self-contained HTML report to FILE (e.g. report.html)",
        default=None,
    )
    scan_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show full remediation advice and code context for each finding",
    )

    # --- 'serve' subcommand ---
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the local AST-Sentinel FastAPI REST API server",
        description=(
            "Launch the built-in FastAPI server that exposes the scan engine\n"
            "over HTTP. Once running, visit /docs for the interactive Swagger UI.\n\n"
            "Useful for integrating AST-Sentinel into CI pipelines or other tooling\n"
            "via the REST API rather than the CLI."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ast-sentinel serve\n"
            "  ast-sentinel serve --port 9000\n"
            "  ast-sentinel serve --host 0.0.0.0 --port 8080\n"
            "\n"
            "Then open: http://localhost:8000/docs\n"
        ),
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        metavar="HOST",
        help="Host/IP to bind the server to (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        metavar="PORT",
        help="TCP port to listen on (default: 8000)",
    )

    args = parser.parse_args()

    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

    if args.command == "scan":
        run_cli(args)
    elif args.command == "serve":
        uvicorn.run("ast_sentinel.main:app", host=args.host, port=args.port, reload=True)
    else:
        parser.print_help()


if __name__ == "__main__":
    run()
