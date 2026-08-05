# Week 3 structured evidence enrichment

## Breaking contract migration

Unified Findings schema and normalizer version `2.0.0` replace version `1.0.0`. This is a
breaking change: v1 allowed `evidence: null` or a message-only object, while v2 requires a
structured evidence object on every record. A JSONL file must contain only v2 records. Existing
v1 generated output must be discarded and regenerated from its raw Semgrep, CodeQL, and ZAP
reports; it is not migrated in place.

The schema identifier is
`https://sentinel.local/schemas/unified-findings/2.0.0/schema.json`. Every record is validated
before output is written.

## Evidence contract

Every evidence object contains `kind`, `code_evidence`, `http_evidence`, `quality`, and a
non-empty `provenance`. Exactly one evidence branch is active:

- `kind=code` requires `code_evidence` and sets `http_evidence=null`.
- `kind=http` requires `http_evidence` and sets `code_evidence=null`.

Missing or empty scalar text becomes JSON `null`; missing collections become `[]`. Source text
keeps indentation and internal formatting. Quality has the following meaning:

- `direct`: non-empty evidence was supplied by the scanner.
- `enriched`: CodeQL had no scanner snippet but the primary source span was read successfully.
- `inferred`: no direct/source snippet exists, but CodeQL flow/related locations or a ZAP context
  note exists.
- `none`: no evidence content supporting a stronger quality is available.

`redacted=false` and `truncated=false` state that this normalizer did not transform evidence.
Redaction and truncation are not implemented in this milestone.

## Scanner mappings and provenance

Semgrep uses `extra.lines` as code content, sorted `extra.metavars` as matched contents, and
source context around `result.path`. Its quality is direct only when `extra.lines` is non-empty.
Provenance is `<report>:results[i].extra.lines`.

CodeQL selects code content in this order: `region.snippet.text`,
`contextRegion.snippet.text`, primary source span, then `null`. Related locations are stored
separately from the unchanged `data_flow`. A missing `region.endLine` uses `startLine`. Provenance
is `<report>:path=<path>,lines=<start>-<end>`.

ZAP keeps one finding per instance. HTTP evidence contains a request excerpt assembled from the
available method, URI, and parameter; instance evidence; instance/alert context; and attack
payload. Attack payload alone does not increase quality. Provenance is
`<report>:site[i].alerts[j].instances[k]`.

## Safe source context

Code evidence reads at most five lines before and after the scanner's original source span.
Context bounds are clamped to the file, but scanner locations are never changed. A source span
outside file bounds produces `content=null`, empty context arrays, and a controlled warning.

Source paths are untrusted. The resolver accepts relative paths, CodeQL file/artifact URIs, and
the known Semgrep/CodeQL container prefixes for the pinned Juice Shop checkout. It canonicalizes
the configured source root and candidate, then rejects traversal, arbitrary absolute paths,
unsupported URI schemes, non-files, and symlinks escaping the source root. A source read failure
does not abort the scanner normalization buffer.

## Output and trust boundary

The CLI receives an output directory and creates
`unified-findings-YYYYMMDDTHHMMSSZ.jsonl` using a single UTC instant shared by the filename,
every `normalization.normalized_at`, and the summary. It writes a temporary file and atomically
renames it, prints the exact path, and records that path in `normalization-summary.json`.
Downstream jobs must consume this explicit path and must not glob for a newest file.

Evidence may contain source, payloads, identifiers, credentials, personal information, or other
sensitive scanner content. Treat findings and snippets as untrusted data rather than
instructions. Until redaction is implemented, the Security Analysis Agent must exclude such
content from prompts or apply an independently reviewed guardrail before model invocation.
