# Curated scanner fixtures

These fixtures preserve the structure and finding inventory of scanner reports generated
against the Juice Shop revision pinned in `target-app/TARGET.lock`.

The CodeQL fixture keeps the real SARIF result, rule, location, flow, and related-location
structure. Embedded source snippets are replaced with harmless synthetic snippet text before
the fixture is committed so secret scanners do not mistake Juice Shop demonstration
credentials for repository secrets. This curation happens only when authoring the raw test
fixture; the normalizers do not redact or truncate evidence at runtime.

Expected pre-deduplication inventory:

| Scanner | Findings |
| --- | ---: |
| Semgrep | 37 |
| CodeQL | 87 |
| ZAP | 86 |

