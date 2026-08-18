"""Typer command-line adapter for the Project Sentinel knowledge base."""

import json
from collections import Counter
from dataclasses import asdict
from typing import Annotated

import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from src.retrieval.build import build_documents as run_document_build
from src.retrieval.build import collect_documents
from src.retrieval.config import (
    DOCUMENT_TYPES,
    DOCUMENTS_PATH,
    INDEX_PATH,
    INDEX_TEMP_PATH,
    MANIFEST_PATH,
)
from src.retrieval.exceptions import (
    KnowledgeBaseError,
    KnowledgeDocumentNotFoundError,
    SourceValidationError,
)
from src.retrieval.indexers.sqlite_fts import build_index as run_index_build
from src.retrieval.indexers.sqlite_fts import validate_sqlite_capabilities
from src.retrieval.normalization import normalize_query
from src.retrieval.service import KnowledgeSearchService, SearchResult
from src.retrieval.storage.jsonl_store import read_documents

app = typer.Typer(no_args_is_help=True, help="Build and search the Project Sentinel security knowledge base.")
console = Console()
error_console = Console(stderr=True)


def _result_dict(result: SearchResult) -> dict[str, object]:
    return asdict(result)


@app.command()
def validate() -> None:
    """Validate all sources, normalized models, JSON Schema, and SQLite capabilities."""
    collection = collect_documents()
    validate_sqlite_capabilities()
    console.print(f"[green]Valid[/green]: {len(collection.documents)} knowledge documents")
    for warning in collection.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")


@app.command("build-documents")
def build_documents_command() -> None:
    """Generate deterministic canonical JSONL and its manifest."""
    result = run_document_build()
    console.print(f"[green]Built[/green] {result.document_count} documents at {result.documents_path}")
    console.print(f"SHA-256: {result.documents_sha256}")
    for warning in result.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")


@app.command("build-index")
def build_index_command() -> None:
    """Generate the atomic SQLite external-content FTS5 index."""
    path = run_index_build()
    console.print(f"[green]Built[/green] knowledge index at {path}")


@app.command("build")
def build_command() -> None:
    """Validate sources, build canonical documents, and build the search index."""
    validate_sqlite_capabilities()
    result = run_document_build()
    path = run_index_build()
    console.print(f"[green]Built[/green] {result.document_count} documents and index {path}")
    console.print(f"SHA-256: {result.documents_sha256}")
    for warning in result.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")


@app.command()
def search(
    query: Annotated[str, typer.Argument(help="Keyword or security identifier to search for.")],
    top_k: Annotated[int, typer.Option("--top-k", min=1, max=50)] = 5,
    doc_type: Annotated[str | None, typer.Option("--doc-type")] = None,
    mode: Annotated[str, typer.Option("--mode", help="Search mode: hybrid, keyword, or semantic.")] = "hybrid",
    json_output: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")] = False,
) -> None:
    """Search with Hybrid (RRF + MMR), Keyword (BM25), or Semantic (Vector) retrieval."""
    results = KnowledgeSearchService().search(
        query=query,
        top_k=top_k,
        doc_type=doc_type,
        mode=mode,  # type: ignore[arg-type]
    )
    normalized = normalize_query(query)
    if json_output:
        payload = {
            "query": query,
            "mode": mode,
            "normalized_query": normalized,
            "results": [_result_dict(result) for result in results],
        }
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if not results:
        console.print("No matching knowledge documents.")
        return
    table = Table(title=f"Knowledge search ({mode}): {query}")
    table.add_column("Rank", justify="right")
    table.add_column("Document")
    table.add_column("Type")
    table.add_column("Title")
    table.add_column("Score")
    for index, result in enumerate(results, start=1):
        table.add_row(
            str(index),
            result.doc_id,
            result.doc_type,
            result.title,
            f"{result.score:.4f}",
        )
        table.add_row("", "", "", result.snippet or result.summary, "")
    console.print(table)


def _canonical_document(doc_id: str) -> dict[str, object]:
    if not DOCUMENTS_PATH.is_file():
        raise SourceValidationError(
            f"Canonical documents not found: {DOCUMENTS_PATH}. Run build-documents first."
        )
    for document in read_documents(DOCUMENTS_PATH):
        if document.doc_id == doc_id:
            return document.to_canonical_dict()
    raise KnowledgeDocumentNotFoundError(f"Knowledge document not found: {doc_id}")


@app.command("inspect")
def inspect_document(
    doc_id: Annotated[str, typer.Argument(help="Canonical document ID to inspect.")],
) -> None:
    """Print one complete document from canonical JSONL."""
    value = json.dumps(_canonical_document(doc_id), ensure_ascii=False, indent=2, sort_keys=True)
    console.print(Syntax(value, "json", word_wrap=True))


@app.command()
def stats() -> None:
    """Show canonical document counts, hash, and index state."""
    manifest: dict[str, object] = {}
    if MANIFEST_PATH.is_file():
        loaded = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            manifest = loaded
    documents = read_documents(DOCUMENTS_PATH) if DOCUMENTS_PATH.is_file() else []
    counts = Counter(document.doc_type for document in documents)
    table = Table(title="Knowledge-base statistics")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Total documents", str(len(documents)))
    for doc_type in DOCUMENT_TYPES:
        table.add_row(doc_type, str(counts.get(doc_type, 0)))
    table.add_row("JSONL hash", str(manifest.get("documents_sha256", "not built")))
    table.add_row("Index path", str(INDEX_PATH))
    table.add_row("Index exists", "yes" if INDEX_PATH.is_file() else "no")
    console.print(table)


@app.command()
def clean() -> None:
    """Remove only generated knowledge documents, manifest, index, and index temporary file."""
    targets = (DOCUMENTS_PATH, MANIFEST_PATH, INDEX_PATH, INDEX_TEMP_PATH)
    for path in targets:
        if path.is_file():
            path.unlink()
            console.print(f"Removed {path}")


def main() -> int:
    """Run the CLI without exposing tracebacks for expected user-facing errors."""
    try:
        app()
    except KnowledgeBaseError as error:
        error_console.print(f"[red]Error:[/red] {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
