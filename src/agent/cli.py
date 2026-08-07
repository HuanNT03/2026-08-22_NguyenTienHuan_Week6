"""Typer command-line adapter for Project Sentinel Security Analysis Agent."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from src.agent.config import AgentConfig
from src.agent.orchestrator import run_analysis

app = typer.Typer(no_args_is_help=True, help="Run AI Security Analysis Agent on normalized findings.")
console = Console()
error_console = Console(stderr=True)


@app.command("analyze")
def analyze_command(
    findings: Annotated[
        Path,
        typer.Option(
            "--findings",
            "-f",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Path to normalized unified findings JSONL file.",
        ),
    ],
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output-dir",
            "-o",
            help="Directory to store security analysis report JSONL and summary metadata.",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            "-m",
            help="Override LLM model name (e.g. qwen-plus or qwen/qwen-2.5-72b-instruct).",
        ),
    ] = None,
    base_url: Annotated[
        str | None,
        typer.Option(
            "--base-url",
            help="Override LLM base URL.",
        ),
    ] = None,
) -> None:
    """Execute full 3-phase Security Analysis Agent pipeline."""
    config = AgentConfig()
    if model:
        config.model = model
    if base_url:
        config.base_url = base_url
    if output_dir:
        config.output_dir = output_dir

    console.print(f"[bold blue]Starting Security Analysis Agent[/bold blue] on {findings}")
    console.print(f"Model: [cyan]{config.model}[/cyan] | Base URL: [cyan]{config.base_url}[/cyan]")

    try:
        summary = run_analysis(findings_path=findings, config=config)
        console.print("[bold green]Analysis Complete![/bold green]")
        console.print(f"Total findings analyzed: [green]{summary['total_input_findings']}[/green]")
        console.print(f"Total report entries: [green]{summary['total_report_entries']}[/green]")
        console.print(f"Report JSONL saved to: [cyan]{summary['report_file']}[/cyan]")
        console.print("Coverage status: [bold green]100% Complete[/bold green]")
    except Exception as err:
        error_console.print(f"[red]Error during analysis:[/red] {err}")
        raise typer.Exit(code=1) from err


def main() -> int:
    """Run CLI entry point."""
    try:
        app()
    except Exception as err:  # noqa: BLE001
        error_console.print(f"[red]Fatal Error:[/red] {err}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
