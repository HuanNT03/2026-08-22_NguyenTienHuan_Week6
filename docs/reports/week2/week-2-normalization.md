# Week 2 unified findings normalization

## Data contract

The Python normalizer converts one Semgrep result, one CodeQL result, or one ZAP instance into
one line in `reports/normalized/unified-findings.jsonl`. Every line is validated against
`schemas/unified_findings.schema.json` and every `raw_sources[].json_pointer` is resolved
against its raw report before the finding is accepted.

Code locations are relative to the Juice Shop source root. HTTP endpoints contain only the URL
path in Week 2. Fingerprints and group keys use canonical JSON with sorted keys, compact
separators, UTF-8 Unicode, and explicit null keys.

CodeQL local và CI scan dùng `--sarif-add-snippets`. Với output SARIF, cờ này thêm
`physicalLocation.region.snippet.text` cho mỗi result location cùng hai dòng ngữ cảnh trước và
sau vị trí được báo cáo; nó không nhúng toàn bộ file.

The v1 normalizer deliberately emits `evidence: null`. It also does not copy CodeQL snippet text
into `data_flow.content`. Scanner content remains untrusted and redaction is deferred to the
guardrail work rather than passing raw evidence or source snippets into the AI pipeline. Raw
SARIF remains available as an ignored local artifact or short-lived CI artifact for audit.

## Scan metadata

Each scanner creates a matching sidecar before scanning:

- `semgrep.meta.json`
- `zap.meta.json`
- `codeql.meta.json`

The sidecar supplies run ID, pipeline ID, scan timestamp, and pinned target identity. Scanner
normalizers do not read CI variables, Git state, `TARGET.lock`, or the clock.

Normalization consumes complete report/metadata pairs:

| Scanner | Report | Metadata |
| --- | --- | --- |
| Semgrep | `semgrep.json` | `semgrep.meta.json` |
| ZAP | `zap.json` | `zap.meta.json` |
| CodeQL | `codeql.sarif` | `codeql.meta.json` |

The metadata sidecar is required. A report without its matching sidecar cannot provide the scan
and target provenance required by the Unified Finding schema. `semgrep.sarif` and `zap.yaml` are
not normalization inputs.

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

Normalization is isolated per tool. A missing report or metadata sidecar marks that tool as
`skipped` with `reason: "missing_input"` and a `missing_files` list. If at least one complete
tool pair succeeds and the remaining tools are only missing, JSONL is written and the CLI exits
zero. If no tool succeeds, the CLI exits non-zero and does not create a success output.

An existing but invalid JSON document, unsupported SARIF, invalid metadata, missing primary
location, schema failure, or unresolved JSON Pointer marks that tool as `failed` and discards
its buffer. Findings from other successful tools are still written, the summary records the
failure, and the CLI exits non-zero.

Scanner diagnostics and recoverable parsing issues produce `partial` status. They are summary
warnings, never unified findings.
