# Project Sentinel Security Knowledge Base

The Week 2 knowledge base provides deterministic English keyword retrieval for security concepts,
scanner findings, and vulnerability examples. It is designed for direct use by both humans and the
Week 3 agent without invoking a CLI subprocess.

The review inventory, exact source paths, and expected counts are maintained in
[`docs/reports/week2/week-2-knowledgebase.md`](../docs/reports/week2/week-2-knowledgebase.md).

## Directory structure

```text
knowledge-base/
├── raw/
│   ├── owasp/       OWASP Top 10:2025 Markdown
│   ├── cwe/         MITRE CWE Views 699 and 1435 CSV
│   ├── semgrep/     Reviewed Semgrep overview and selected-rule Markdown
│   └── zap/         Reviewed ZAP overview and selected-alert Markdown
├── curated/examples/  One authored vulnerability example per YAML file
├── processed/         Canonical documents.jsonl and deterministic manifest.json
└── index/             Generated SQLite FTS5 database; never committed
```

`raw` preserves imported or scanner-oriented source material. `curated` contains Project Sentinel
examples maintained as individual review units. `processed` is normalized canonical data.
`index` contains only rebuildable local artifacts.

## Installation

Python 3.11 or newer is required. The selected Python runtime must include SQLite JSON functions
and FTS5. `make install` checks these capabilities, repairs an incompatible project `.venv`, and
falls back to a compatible system Python when the requested interpreter (including a pyenv build)
does not provide `_sqlite3`.

```bash
make install
make kb-validate
```

If no compatible interpreter is selected automatically, try
`make install PYTHON=/usr/bin/python3`. On Ubuntu/Debian, a pyenv Python must be rebuilt after
installing `libsqlite3-dev`; installing a package named `sqlite3` with pip cannot add CPython's
missing `_sqlite3` extension.

The repository uses `pyproject.toml` as authoritative package metadata. `requirements.txt` mirrors
the supported ranges for environments that require that format.

## Build

```bash
make kb-build-documents
make kb-build-index

# Or validate and build both stages:
make kb-build
```

The canonical files are:

- `knowledge-base/processed/documents.jsonl`
- `knowledge-base/processed/manifest.json`

The generated index is `knowledge-base/index/knowledge.db`.

## Search

```bash
make kb-search QUERY="SQL Injection"
make kb-search QUERY="XSS" TOP_K=5
make kb-search QUERY="IDOR" DOC_TYPE=cwe

.venv/bin/python -m src.retrieval.cli search "CWE89" --json
```

Search performs Unicode NFKC and whitespace normalization, canonicalizes CWE and OWASP IDs, and
constructs FTS5 `MATCH` expressions only from quoted allowlisted tokens. Raw queries are never
passed directly to `MATCH`.

Ranking uses:

1. exact identifier match;
2. exact title match;
3. exact alias match;
4. weighted BM25, smaller score first;
5. deterministic `doc_id` ordering.

When multiple documents map to the same identifier, its canonical CWE or OWASP category owns the
identifier tie before BM25. This ensures `CWE79` returns `cwe-79` rather than an example that merely
maps to CWE-79.

## Python service

Agents import the service directly:

```python
from src.retrieval.service import KnowledgeSearchService

service = KnowledgeSearchService()
results = service.search("SQL Injection", top_k=5)
```

`SearchResult.bm25_score` is a ranking score, not confidence or exploitability.

## Inspect and statistics

```bash
make kb-inspect DOC_ID=cwe-89
make kb-stats
```

Inspect reads canonical JSONL, so it returns fields not required by the search index, including
optional detectability metadata.

## Adding a curated example

1. Add one English YAML file under `knowledge-base/curated/examples/`.
2. Use a lowercase deterministic `example-*` ID.
3. Provide `id`, `title`, `description`, identifiers, tags, vulnerable behavior, and remediation.
4. If present, detectability values must be `high`, `medium`, `low`, or `unknown`.
5. Add its path, ID, and primary mappings to `docs/reports/week2/week-2-knowledgebase.md`.
6. Run `make kb-validate`, `make kb-build`, and `make kb-test`.

Duplicate IDs fail with both the first and conflicting source paths.

## Adding a scanner document

Add Markdown below `knowledge-base/raw/semgrep/` or `knowledge-base/raw/zap/`. Every file begins
with YAML front matter containing:

```yaml
---
id: scanner-document-id
doc_type: scanner_document
title: Scanner document title
aliases: []
summary: Concise retrieval summary.
identifiers: {}
tags: [scanner]
source_name: Verified source name
source_version: 1.0.0
source_locator: Source-specific locator
---
```

Use `scanner_rule` for a selected rule or alert. Document the path and canonical ID in the inventory
before rebuilding.

## Deterministic output

- All documents pass the Pydantic model and JSON Schema.
- A global registry rejects duplicate `doc_id` values.
- CWE records shared by Views 699 and 1435 coalesce only when every CSV field is identical.
- Documents sort by `doc_id`.
- JSON uses UTF-8, stable key ordering, compact separators, and one newline-terminated object per line.
- Optional null fields are omitted.
- The manifest contains no timestamp.
- `documents_sha256` hashes the exact JSONL bytes.

`documents.jsonl` and `manifest.json` are committed because the dataset is small, supports Git
review, and lets the Week 3 agent work without first running parsers. `knowledge.db` is not committed
because it is platform-generated and can be rebuilt completely from canonical JSONL.

## Cleanup

```bash
make kb-clean
```

This command removes only canonical generated files and the SQLite database/temporary database. It
never deletes `raw` or `curated` sources. Recreate everything with `make kb-build`.

## Data sources and attribution

### OWASP Top 10

- Publisher: OWASP Foundation.
- Dataset: OWASP Top 10:2025.
- Local path: `knowledge-base/raw/owasp/`.
- Source: <https://owasp.org/Top10/2025/> and <https://github.com/OWASP/Top10>.
- License: Creative Commons Attribution-ShareAlike 4.0 International, as declared in the official
  repository: <https://github.com/OWASP/Top10/blob/master/LICENSE>.
- Modification notice: content is parsed, sectioned, stripped of score tables, and normalized for
  retrieval.

### MITRE CWE

- Publisher: The MITRE Corporation.
- Datasets: CWE View 699 Software Development and CWE View 1435 2024 CWE Top 25.
- Local paths: `knowledge-base/raw/cwe/699.csv` and `knowledge-base/raw/cwe/1435.csv`.
- Sources: <https://cwe.mitre.org/data/definitions/699.html> and
  <https://cwe.mitre.org/data/definitions/1435.html>.
- Terms: <https://cwe.mitre.org/about/termsofuse.html>. CWE is available for research,
  development, and commercial use subject to retention of MITRE's copyright designation and terms.
- Modification notice: structured fields are converted to plain text and overlapping view records
  are deterministically coalesced.

### Semgrep

- Source: <https://semgrep.dev/docs/writing-rules/glossary> and scanner metadata observed in
  `reports/raw/semgrep.json`.
- Local path: `knowledge-base/raw/semgrep/`.
- Scanner version: 1.171.0.
- The local Markdown is a Project Sentinel-authored summary, not a copy of the full documentation.
- TODO: verify source documentation license/terms before redistributing substantial excerpts.

### OWASP ZAP

- Sources: <https://www.zaproxy.org/docs/desktop/start/features/alerts/> and
  <https://www.zaproxy.org/docs/alerts/>.
- Local path: `knowledge-base/raw/zap/`.
- Scanner version: 2.17.0.
- The local Markdown is a Project Sentinel-authored summary combined with fields observed in
  `reports/raw/zap.json`.
- TODO: verify source documentation license/terms before redistributing substantial excerpts.

### Curated examples

The examples under `knowledge-base/curated/examples/` are authored for Project Sentinel. They are
educational minimal examples and are not production-ready framework recipes.

## Current limitations and future direction

The current system supports English keyword retrieval only. It has no HTTP API, embeddings, vector
database, RAG, hybrid retrieval, AI reranking, graph database, or automatic OWASP-to-CWE relations.

A later semantic or hybrid implementation can retain `KnowledgeDocument` and
`KnowledgeSearchService` as the ingestion and application boundaries, add embeddings as generated
artifacts, and fuse semantic scores with existing exact/BM25 results without changing canonical
JSONL.
