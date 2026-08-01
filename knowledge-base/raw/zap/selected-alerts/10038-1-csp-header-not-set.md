---
id: zap-alert-10038-1
doc_type: scanner_rule
title: ZAP 10038-1 Content Security Policy Header Not Set
aliases: [CSP Header Not Set, Missing Content Security Policy, ZAP 10038]
summary: ZAP raises alert 10038-1 when an HTML response does not provide a recognized Content Security Policy.
identifiers:
  cwe: [CWE-693]
  zap: ['10038', '10038-1']
tags: [zap, dast, csp, security-header, misconfiguration]
source_name: OWASP ZAP alert documentation and Project Sentinel Week 1 scan
source_version: 2.17.0
source_locator: '10038-1'
---

# Content Security Policy header not set

## Observed alert

The Week 1 report contains alert reference `10038-1` with five instances. Its native classification
is Medium risk and High confidence, with CWE-693 and WASC-15 metadata.

## Detection meaning

The passive rule checks eligible HTML responses for recognized CSP headers or a policy delivered by
a supported HTML mechanism. Missing CSP removes a defense-in-depth control against script and
content injection; it does not independently prove that an injection vulnerability exists.

## Evidence

Evidence may be empty because the missing header itself triggers the alert. Review all response
paths to decide whether one consistent policy can be deployed.

## Recommended remediation

Deploy a restrictive `Content-Security-Policy`, begin with reporting if necessary, avoid broad
wildcards and unsafe script directives, and test required application resources.
