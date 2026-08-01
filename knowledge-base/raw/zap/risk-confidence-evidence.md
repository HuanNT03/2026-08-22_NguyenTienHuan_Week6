---
id: zap-risk-confidence-evidence
doc_type: scanner_document
title: ZAP Risk, Confidence, Evidence, CWE, and WASC
aliases: [ZAP Risk, ZAP Confidence, ZAP Evidence, ZAP CWE, ZAP WASC]
summary: ZAP risk, confidence, evidence, CWE, and WASC fields answer different triage questions and must not be conflated.
identifiers: {zap: [zap-alert-fields]}
tags: [zap, dast, risk, confidence, evidence, cwe, wasc]
source_name: OWASP ZAP documentation and Project Sentinel Week 1 scan
source_version: 2.17.0
source_locator: ZAP alert fields
---

# ZAP alert classification fields

## Risk

Risk is the alert's relative severity: Informational, Low, Medium, or High. It does not indicate
whether the specific instance has been manually confirmed.

## Confidence

Confidence describes how strongly ZAP believes the alert is valid. Native levels include False
Positive, Low, Medium, High, and Confirmed, although scanner-generated alerts are not normally
raised as False Positive or Confirmed.

## Evidence

Evidence is a request or response string used to support the alert. It may be empty when absence is
the evidence, such as a missing response header.

## CWE and WASC

CWE identifies a weakness category and WASC identifies a web security threat classification. A
missing or negative native identifier must remain unknown rather than becoming a fabricated mapping.

## Triage use

Keep risk, confidence, and evidence separate. Confirm the behavior in application context before
assigning exploitability or business impact.
