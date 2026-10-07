from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ast_sentinel.metrics.risk_score import risk_grade
from ast_sentinel.schemas.findings import ScanResult

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def generate_html_report(result: ScanResult, output_path: Path | None = None) -> str:
    """Render ScanResult into a self-contained HTML report."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")

    grade = risk_grade(result.risk_score) if result.risk_score is not None else "N/A"

    html = template.render(
        result=result,
        grade=grade,
    )

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

    return html
