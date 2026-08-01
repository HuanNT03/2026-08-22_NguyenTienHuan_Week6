---
id: semgrep-rule-metadata
doc_type: scanner_document
title: Semgrep Rule ID, Severity, and Metadata
aliases: [Semgrep Rule Metadata, Semgrep Rule ID, Semgrep Severity]
summary: Semgrep rule metadata supplies taxonomy and triage context but must be interpreted separately from match evidence.
identifiers: {semgrep: [semgrep-rule-metadata]}
tags: [semgrep, sast, rule, severity, confidence, metadata]
source_name: Semgrep documentation and Project Sentinel Week 1 scan
source_version: 1.171.0
source_locator: reports/raw/semgrep.json extra.metadata
---

# Semgrep rule metadata

## Rule ID and message

The fully qualified `check_id` identifies the rule. The message describes the dangerous pattern or
taint flow and usually contains the first remediation clue. Registry rule content can change even
when the Semgrep CLI version is pinned, so the raw report remains the run-specific evidence.

## Severity and confidence

Severity communicates the rule author's impact classification. Confidence, when present, estimates
how reliably the pattern represents the intended issue. Neither field is a proof of exploitability,
and missing confidence must be represented as unknown rather than inferred from severity.

## Taxonomy metadata

Metadata can include `cwe`, `owasp`, vulnerability class, category, technology, references, and
license information. Values may be strings or arrays and must be normalized without losing the
native rule ID.

## Recommended use

Correlate rule metadata with the code location, data-flow trace, application trust boundaries, and
runtime controls. Preserve the scanner-native values alongside normalized severity and confidence.
