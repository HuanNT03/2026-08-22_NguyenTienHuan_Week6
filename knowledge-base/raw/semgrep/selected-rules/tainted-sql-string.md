---
id: semgrep-rule-javascript-express-security-injection-tainted-sql-string-tainted-sql-string
doc_type: scanner_rule
title: Semgrep Tainted SQL String Rule
aliases: [Tainted SQL String, SQL Injection Rule, SQLi]
summary: Detects Express request data used to construct an SQL string, which can permit SQL injection.
identifiers:
  cwe: [CWE-89]
  owasp: [A05:2025]
  semgrep: [javascript.express.security.injection.tainted-sql-string.tainted-sql-string]
tags: [semgrep, sast, sql, injection, express, javascript]
source_name: Semgrep rule metadata and Project Sentinel Week 1 scan
source_version: 1.171.0
source_locator: javascript.express.security.injection.tainted-sql-string.tainted-sql-string
---

# Tainted SQL string

## Observed finding

The Week 1 report contains six findings for this rule. It reports user input used to manually
construct an SQL string and assigns native severity `ERROR`.

## Detection meaning

The rule follows data from an Express request into SQL string construction. Review the trace to
confirm the source is attacker controlled and that the final string reaches a database execution
API. Escaping applied for another context is not a substitute for SQL parameter binding.

## Recommended remediation

Use parameterized queries or a query builder that binds values separately from SQL syntax. Apply
least-privilege database permissions and add negative tests using quote and Boolean payloads.

## Source reference

Observed in `reports/raw/semgrep.json`. Rule metadata maps the result to CWE-89 and OWASP A05:2025.
