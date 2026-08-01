---
id: zap-alert-anatomy
doc_type: scanner_document
title: OWASP ZAP Alert Anatomy
aliases: [ZAP Alert, ZAP Finding]
summary: A ZAP alert combines generic scan-rule guidance with request-specific URL, parameter, attack, and evidence fields.
identifiers: {zap: [zap-alert]}
tags: [zap, dast, alert, web-security]
source_name: OWASP ZAP documentation and Project Sentinel Week 1 scan
source_version: 2.17.0
source_locator: reports/raw/zap.json alerts
---

# ZAP alert anatomy

A ZAP alert is a potential vulnerability associated with a request. Passive and active scan rules,
scripts, add-ons, or a reviewer can raise alerts.

## Generic fields

- Name and Alert Reference identify the alert family and subtype.
- Risk expresses relative severity.
- Confidence expresses how strongly the evidence supports the alert.
- CWE, WASC, description, solution, references, and tags provide classification and guidance.

## Instance fields

URL, HTTP method, parameter, attack payload, and evidence describe a particular occurrence. A rule
can produce multiple instances with the same generic alert information.

## Review guidance

Inspect the affected response and security context. Missing-header evidence can legitimately be
empty because absence is the condition detected. Treat generic solutions as starting points because
ZAP does not know the application's source-code architecture.

## Source reference

This summary follows the official ZAP alert field documentation and the fields present in
`reports/raw/zap.json`.
