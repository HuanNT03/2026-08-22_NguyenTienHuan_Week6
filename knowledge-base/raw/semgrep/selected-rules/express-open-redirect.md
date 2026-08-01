---
id: semgrep-rule-javascript-express-security-audit-express-open-redirect-express-open-redirect
doc_type: scanner_rule
title: Semgrep Express Open Redirect Rule
aliases: [Express Open Redirect, Unvalidated Redirect, CWE-601]
summary: Detects an Express redirect whose destination can be influenced by request input.
identifiers:
  cwe: [CWE-601]
  owasp: [A01:2025]
  semgrep: [javascript.express.security.audit.express-open-redirect.express-open-redirect]
tags: [semgrep, sast, open-redirect, express, javascript]
source_name: Semgrep rule metadata and Project Sentinel Week 1 scan
source_version: 1.171.0
source_locator: javascript.express.security.audit.express-open-redirect.express-open-redirect
---

# Express open redirect

## Observed finding

The Week 1 report contains one finding for this rule with native severity `WARNING`. The scanner
reports a URL specified by user input reaching an Express redirect operation.

## Detection meaning

An attacker-controlled redirect target can send users from a trusted application to a phishing
site. It can also expose authorization codes or tokens when used in an authentication flow.

## Recommended remediation

Prefer server-side destination identifiers. If a path must be accepted, parse it and allow only
normalized same-origin relative paths. Do not validate with substring or suffix comparisons.

## Source reference

Observed in `reports/raw/semgrep.json`. Rule metadata maps the result to CWE-601 and OWASP A01:2025.
