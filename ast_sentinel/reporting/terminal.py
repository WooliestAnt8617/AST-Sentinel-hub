from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ast_sentinel.metrics.risk_score import risk_grade
from ast_sentinel.schemas.findings import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def print_terminal_report(result: ScanResult, verbose: bool = False):
    """Print a Rich-formatted terminal summary."""
    console = Console()

    # Header
    grade = risk_grade(result.risk_score) if result.risk_score is not None else "N/A"
    score_text = f"{result.risk_score:.1f}/100" if result.risk_score is not None else "N/A"

    header = Text()
    header.append("AST-Sentinel Scan Report\n", style="bold white")
    header.append(f"Scan ID: {result.scan_id}\n", style="dim")
    header.append(f"Timestamp: {result.timestamp}\n", style="dim")
    header.append(f"Risk Score: {score_text}  Grade: {grade}", style="bold")
    console.print(Panel(header, border_style="blue"))

    # Summary table
    summary_table = Table(title="Summary", show_header=True, header_style="bold")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")
    summary_table.add_row("Files Analyzed", str(result.summary.total_files))
    summary_table.add_row("Total Findings", str(result.summary.total_findings))
    summary_table.add_row("[bold red]Critical[/]", str(result.summary.critical_count))
    summary_table.add_row("[red]High[/]", str(result.summary.high_count))
    summary_table.add_row("[yellow]Medium[/]", str(result.summary.medium_count))
    summary_table.add_row("[cyan]Low[/]", str(result.summary.low_count))
    summary_table.add_row("[dim]Info[/]", str(result.summary.info_count))
    console.print(summary_table)

    if result.summary.total_findings == 0:
        console.print("\n[bold green][+] No security findings detected.[/]\n")
        return

    # Findings table
    findings_table = Table(title="Findings", show_header=True, header_style="bold", show_lines=True)
    findings_table.add_column("#", style="dim", width=4)
    findings_table.add_column("Severity", width=10)
    findings_table.add_column("Rule", width=28)
    findings_table.add_column("File", width=30)
    findings_table.add_column("Line", width=6, justify="right")
    findings_table.add_column("Message", min_width=40)

    idx = 0
    for fa in result.files_analyzed:
        for finding in fa.findings:
            idx += 1
            sev_style = SEVERITY_COLORS.get(finding.severity, "white")
            findings_table.add_row(
                str(idx),
                Text(finding.severity.value, style=sev_style),
                finding.rule_name,
                finding.location.file_path.split("/")[-1].split("\\")[-1],
                str(finding.location.line_number),
                finding.message,
            )

    console.print(findings_table)

    if verbose:
        console.print("\n[bold]Detailed Remediation:[/]")
        idx = 0
        for fa in result.files_analyzed:
            for finding in fa.findings:
                idx += 1
                if finding.remediation:
                    console.print(f"  [{idx}] {finding.remediation}", style="dim")
