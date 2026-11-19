# CVE-YYYY-NNNNN — Short title of the vulnerability

<!--
This README is the writeup shown on the BlackHalo site.
Keep it in the root of the research repository (e.g. gpheheise/CVE-YYYY-NNNNN).
The first H1 is hidden on the site because the site shows the title itself.
Relative links and images (./poc, ./img/diagram.png) are rewritten to GitHub automatically.
-->

| | |
|---|---|
| **Product** | Vendor Product x.y.z – a.b.c |
| **Fixed in** | a.b.d |
| **CVSS v3.1** | 0.0 · `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Weakness** | CWE-### · Name |
| **Discovered by** | BlackHalo, Lufthansa Industry Solutions |

## Summary

Two or three sentences: what is vulnerable, who can reach it, and what they gain.

## Root cause

Where the bug lives and why it happens. Short code excerpts are fine.

## Reproduction

Minimal steps against a local test instance. Link the full proof of concept in [`poc/`](poc/).

## Impact

- What an attacker can do
- Under which preconditions

## Detection

Log lines, indicators or queries defenders can use.

## Remediation

Fixed version, plus interim mitigations.

## Timeline

| Date | Event |
|---|---|
| YYYY-MM-DD | Reported to vendor |
| YYYY-MM-DD | Vendor acknowledged |
| YYYY-MM-DD | Fix released |
| YYYY-MM-DD | Public disclosure |
