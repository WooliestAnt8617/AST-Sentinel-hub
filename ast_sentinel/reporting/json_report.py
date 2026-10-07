from pathlib import Path

from ast_sentinel.schemas.findings import ScanResult


def generate_json_report(result: ScanResult, output_path: Path | None = None) -> str:
    """Serialize ScanResult to pretty-printed JSON."""
    report_json = result.model_dump_json(indent=2)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_json, encoding="utf-8")

    return report_json
