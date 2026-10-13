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
        description="AST-Sentinel: Static Source Code Security Audit Engine"
    )
    subparsers = parser.add_subparsers(dest="command")

    # --- 'scan' subcommand ---
    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("target", help="Path to a .py file or directory to scan")
    scan_parser.add_argument("--json", help="Output JSON report to this path", default=None)
    scan_parser.add_argument("--html", help="Output HTML report to this path", default=None)
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed remediation info")

    # --- 'serve' subcommand ---
    serve_parser = subparsers.add_parser("serve", help="Start the FastAPI API server")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)

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
