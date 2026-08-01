---
id: zap-alert-10098
doc_type: scanner_rule
title: ZAP 10098 Cross-Domain Misconfiguration
aliases: [Cross-Domain Misconfiguration, CORS Misconfiguration, ZAP 10098]
summary: ZAP raises alert 10098 when cross-origin policy may allow untrusted websites to read server data.
identifiers:
  cwe: [CWE-264]
  owasp: [A01:2025]
  zap: ['10098']
tags: [zap, dast, cors, cross-origin, misconfiguration]
source_name: OWASP ZAP alert documentation and Project Sentinel Week 1 scan
source_version: 2.17.0
source_locator: '10098'
---

# Cross-domain misconfiguration

## Observed alert

The Week 1 report contains alert reference `10098` with three instances. Its native classification
is Medium risk and Medium confidence, with CWE-264 and WASC-14 metadata.

## Detection meaning

The passive rule identifies a permissive cross-origin response policy. Practical impact depends on
whether sensitive data is returned, whether credentials are involved, and which origins browsers
are allowed to read from.

## Evidence

Review the `Access-Control-Allow-Origin` and credential-related response headers together with the
request Origin and authentication model.

## Recommended remediation

Allow only exact trusted origins that require browser access. Avoid reflecting arbitrary Origin
values, reject the `null` origin unless explicitly needed, and do not enable credentials broadly.
