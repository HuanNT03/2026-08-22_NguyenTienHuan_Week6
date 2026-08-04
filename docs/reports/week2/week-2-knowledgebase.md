# Week 2 security knowledge base

This document is the review inventory and implementation contract for the Project Sentinel
keyword-search knowledge base. It is intentionally explicit so source additions cannot silently
change the canonical dataset.

## Architecture and data flow

```text
OWASP Markdown ─┐
CWE CSV views ──┼─> parsers -> validated KnowledgeDocument registry
Scanner Markdown┤                      |
Curated YAML ───┘                      v
                         processed/documents.jsonl
                                      |
                                      v
                         index/knowledge.db (FTS5)
```

`documents.jsonl` is the small, reviewable canonical dataset. The SQLite database is a generated
external-content FTS5 index and is never committed.

## CWE source inventory and coalescing policy

| View | Path | Input records |
| --- | --- | ---: |
| CWE-699 Software Development | `knowledge-base/raw/cwe/699.csv` | 399 |
| CWE-1435 2024 CWE Top 25 | `knowledge-base/raw/cwe/1435.csv` | 25 |

Both files are parsed and validated independently. Fifteen records occur in both views and are
currently field-for-field identical. View 699 is the primary source for those records. A shared
record is coalesced only when every CSV field is identical; any difference fails the build with the
CWE ID, both paths, and the conflicting fields. The 25 View 1435 members receive the tags
`cwe-view-1435` and `cwe-top-25`. This produces 409 unique CWE documents from 424 input rows.

## Curated vulnerability example inventory

Each example is an independent English-language YAML source.

| Raw path | Canonical document ID | Primary mapping |
| --- | --- | --- |
| `knowledge-base/curated/examples/sql-injection-nodejs.yml` | `example-sql-injection-nodejs` | CWE-89 / A05:2025 |
| `knowledge-base/curated/examples/reflected-xss-express.yml` | `example-reflected-xss-express` | CWE-79 / A05:2025 |
| `knowledge-base/curated/examples/stored-xss.yml` | `example-stored-xss` | CWE-79 / A05:2025 |
| `knowledge-base/curated/examples/dom-based-xss.yml` | `example-dom-based-xss` | CWE-79 / A05:2025 |
| `knowledge-base/curated/examples/idor.yml` | `example-idor` | CWE-639 / A01:2025 |
| `knowledge-base/curated/examples/missing-function-level-authorization.yml` | `example-missing-function-level-authorization` | CWE-862 / A01:2025 |
| `knowledge-base/curated/examples/authentication-bypass.yml` | `example-authentication-bypass` | CWE-306 / A07:2025 |
| `knowledge-base/curated/examples/csrf.yml` | `example-csrf` | CWE-352 / A01:2025 |
| `knowledge-base/curated/examples/path-traversal.yml` | `example-path-traversal` | CWE-22 / A01:2025 |
| `knowledge-base/curated/examples/os-command-injection.yml` | `example-os-command-injection` | CWE-78 / A05:2025 |
| `knowledge-base/curated/examples/ssrf.yml` | `example-ssrf` | CWE-918 / A01:2025 |
| `knowledge-base/curated/examples/open-redirect.yml` | `example-open-redirect` | CWE-601 / A01:2025 |
| `knowledge-base/curated/examples/unrestricted-file-upload.yml` | `example-unrestricted-file-upload` | CWE-434 / A08:2025 |
| `knowledge-base/curated/examples/xxe.yml` | `example-xxe` | CWE-611 / A05:2025 |
| `knowledge-base/curated/examples/cors-misconfiguration.yml` | `example-cors-misconfiguration` | CWE-942 / A02:2025 |

## Scanner document inventory

The selected rules and alerts are taken from the checked-in Week 1 reports rather than invented
examples. Scanner versions are pinned in `configs/tool-versions.env`.

### Overview documents

| Raw path | Canonical document ID |
| --- | --- |
| `knowledge-base/raw/semgrep/finding-anatomy.md` | `semgrep-finding-anatomy` |
| `knowledge-base/raw/semgrep/rule-metadata.md` | `semgrep-rule-metadata` |
| `knowledge-base/raw/zap/alert-anatomy.md` | `zap-alert-anatomy` |
| `knowledge-base/raw/zap/risk-confidence-evidence.md` | `zap-risk-confidence-evidence` |

### Selected rule and alert documents

| Raw path | Canonical document ID | Week 1 observation |
| --- | --- | --- |
| `knowledge-base/raw/semgrep/selected-rules/tainted-sql-string.md` | `semgrep-rule-javascript-express-security-injection-tainted-sql-string-tainted-sql-string` | 6 findings |
| `knowledge-base/raw/semgrep/selected-rules/express-open-redirect.md` | `semgrep-rule-javascript-express-security-audit-express-open-redirect-express-open-redirect` | 1 finding |
| `knowledge-base/raw/zap/selected-alerts/10038-1-csp-header-not-set.md` | `zap-alert-10038-1` | 5 instances |
| `knowledge-base/raw/zap/selected-alerts/10098-cross-domain-misconfiguration.md` | `zap-alert-10098` | 3 instances |

## Expected canonical document counts

| Document type | Count |
| --- | ---: |
| `cwe` | 409 |
| `owasp_category` | 10 |
| `vulnerability_example` | 15 |
| `scanner_document` | 4 |
| `scanner_rule` | 4 |
| **Total** | **442** |

The manifest also records 399 View 699 rows, 25 View 1435 rows, and 15 coalesced rows. It contains
no timestamp; its SHA-256 is computed from the exact sorted JSONL bytes.

## Build and acceptance commands

```bash
make install
make kb-validate
make kb-build
make kb-stats
make kb-test
make kb-lint
```

Search acceptance includes SQL Injection, SQLi, XSS, CWE79, Broken Access Control, Security
Misconfiguration, IDOR, and XXE. Query syntax is tokenized and quoted before FTS5 `MATCH`.

## Attribution review

- OWASP Foundation, OWASP Top 10:2025, normalized from local Markdown. The official repository is
  licensed under Creative Commons Attribution-ShareAlike 4.0.
- The MITRE Corporation, CWE Views 699 and 1435, normalized from local CSV files. Use is subject to
  the official CWE Terms of Use and requires retention of MITRE's copyright designation and terms.
- Semgrep 1.171.0 documentation and the local Week 1 Semgrep JSON report.
- OWASP ZAP 2.17.0 documentation and the local Week 1 ZAP JSON report.

Exact source URLs and license/terms links are maintained in `knowledge-base/README.md`. A source
whose terms cannot be verified must be marked `TODO: verify source license/terms`; terms must not
be guessed.

## Current limitations

This iteration supports deterministic English keyword search only. It intentionally excludes HTTP
APIs, embeddings, semantic or hybrid search, RAG, vector databases, reranking, graph relationships,
and automatic relationships between OWASP and CWE documents.
