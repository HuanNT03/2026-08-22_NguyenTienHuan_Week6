---
id: semgrep-finding-anatomy
doc_type: scanner_document
title: Semgrep Finding Anatomy
aliases: [Semgrep Finding, Semgrep Result]
summary: A Semgrep finding records a rule match, source location, message, severity, metadata, and optional data-flow evidence.
identifiers: {semgrep: [semgrep-finding]}
tags: [semgrep, sast, finding, static-analysis]
source_name: Semgrep documentation and Project Sentinel Week 1 scan
source_version: 1.171.0
source_locator: reports/raw/semgrep.json results
---

# Semgrep finding anatomy

A finding is produced when a Semgrep rule matches source code. A match is evidence that code
satisfies the rule pattern; it is not by itself proof that the issue is exploitable.

## Important fields

- `check_id` identifies the rule and should remain stable when triaging repeated scans.
- `path`, `start`, and `end` locate the matched source range.
- `extra.message` explains what the rule detected.
- `extra.severity` is the rule's native severity, not exploitability confidence.
- `extra.metadata` may contain CWE, OWASP, confidence, references, category, and technology.
- `extra.dataflow_trace` can identify taint sources, intermediate values, and sinks.

## Review guidance

Confirm that the matched value is attacker controlled, follows the reported flow, and reaches a
security-sensitive operation without an effective validation or encoding control. Record false
positive rationale rather than deleting raw evidence.

## Source reference

This summary is based on Semgrep documentation and fields observed in
`reports/raw/semgrep.json` from the Project Sentinel Week 1 scan.
