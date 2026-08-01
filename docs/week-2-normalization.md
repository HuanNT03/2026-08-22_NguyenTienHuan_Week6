# Week 2 unified findings normalization

## Data contract

The Python normalizer converts one Semgrep result, one CodeQL result, or one ZAP instance into
one line in `reports/normalized/unified-findings.jsonl`. Every line is validated against
`schemas/unified_findings.schema.json` and every `raw_sources[].json_pointer` is resolved
against its raw report before the finding is accepted.

Code locations are relative to the Juice Shop source root. HTTP endpoints contain only the URL
path in Week 2. Fingerprints and group keys use canonical JSON with sorted keys, compact
separators, UTF-8 Unicode, and explicit null keys.

The v1 normalizer deliberately emits `evidence: null`. Scanner content remains untrusted and
redaction is deferred to the guardrail work rather than passing raw evidence into the AI
pipeline.

## Scan metadata

Each scanner creates a matching sidecar before scanning:

- `semgrep.meta.json`
- `zap.meta.json`
- `codeql.meta.json`

The sidecar supplies run ID, pipeline ID, scan timestamp, and pinned target identity. Scanner
normalizers do not read CI variables, Git state, `TARGET.lock`, or the clock.

## Local usage

Create and activate a Python 3.11+ virtual environment, then install the project:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[dev]'
```

Run the scanner workflow to generate fresh raw reports and authoritative sidecars, then:

```bash
make normalize
```

The aggregate CLI can also be called directly:

```bash
python -m src.normalizers.cli normalize-all \
  --raw-dir reports/raw \
  --output reports/normalized/unified-findings.jsonl
```

A single report uses `--tool`, `--input`, `--metadata`, `--output`, and optionally
`--schema` or `--summary`.

## Failure behavior

Normalization is isolated per tool. Invalid JSON, unsupported SARIF, missing primary location,
schema failure, or an unresolved JSON Pointer marks that tool as failed and discards its
buffer. Findings from other successful tools are still written, the summary records the
failure, and the CLI exits non-zero.

Scanner diagnostics and recoverable parsing issues produce `partial` status. They are summary
warnings, never unified findings.
