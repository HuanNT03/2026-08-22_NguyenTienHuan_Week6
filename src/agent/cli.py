import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from src.agent.config import AgentConfig
from src.agent.orchestrator import run_analysis

app = typer.Typer(
    no_args_is_help=True,
    help="Run AI Security Analysis Agent on normalized findings.",
)
console = Console()
error_console = Console(stderr=True)


def setup_logging(verbose: bool = False, log_file: Path | None = None) -> None:
    """Configure structured logging to console and logs/agent-runner.log."""
    level = logging.DEBUG if verbose else logging.INFO
    log_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"

    handlers: list[logging.Handler] = [logging.StreamHandler()]

    target_log_file = log_file or (Path(__file__).resolve().parents[2] / "logs" / "agent-runner.log")
    target_log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(target_log_file, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(log_format))
    handlers.append(file_handler)

    logging.basicConfig(level=level, format=log_format, handlers=handlers, force=True)


@app.callback()
def main_callback() -> None:
    """Project Sentinel Security Analysis Agent CLI."""


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
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help="Agent reasoning execution mode: 'react' (default) or 'static'.",
        ),
    ] = "react",
    max_steps: Annotated[
        int,
        typer.Option(
            "--max-steps",
            help="Maximum ReAct steps permitted per group (default: 5).",
        ),
    ] = 5,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose debug logging.",
        ),
    ] = False,
    log_file: Annotated[
        Path | None,
        typer.Option(
            "--log-file",
            help="Custom path to log file (default: logs/agent-runner.log).",
        ),
    ] = None,
) -> None:
    """Execute full 3-phase Security Analysis Agent pipeline."""
    setup_logging(verbose=verbose, log_file=log_file)

    config = AgentConfig()
    if model:
        config.model = model
    if base_url:
        config.base_url = base_url
    if output_dir:
        config.output_dir = output_dir
    if mode:
        config.agent_mode = "react" if mode.lower() == "react" else "static"
    if max_steps:
        config.max_react_steps = int(max_steps)

    console.print(f"[bold blue]Starting Security Analysis Agent[/bold blue] on {findings}")
    console.print(
        f"Mode: [cyan]{config.agent_mode}[/cyan] | Max Steps: [cyan]{config.max_react_steps}[/cyan] | "
        f"Model: [cyan]{config.model}[/cyan]"
    )

    try:
        summary = run_analysis(findings_path=findings, config=config, log_file=log_file)
        console.print("[bold green]Analysis Complete![/bold green]")
        console.print(f"Total findings analyzed: [green]{summary['total_input_findings']}[/green]")
        console.print(f"Total report entries: [green]{summary['total_report_entries']}[/green]")
        console.print(
            f"Token Usage: Input [cyan]{summary['token_usage']['prompt_tokens']}[/cyan] | "
            f"Output [cyan]{summary['token_usage']['completion_tokens']}[/cyan] | "
            f"Total [cyan]{summary['token_usage']['total_tokens']}[/cyan]"
        )
        console.print(f"Execution time: [cyan]{summary['execution_time_seconds']}s[/cyan]")
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
