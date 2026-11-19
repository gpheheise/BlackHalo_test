# Security policy and coordinated disclosure

BlackHalo, the offensive-security platform of Lufthansa Industry Solutions, practises coordinated
vulnerability disclosure. This page covers how we publish what we find and how to report issues to us.

## Reporting a vulnerability to us

- **Email:** security@blackhalo.example *(replace with the real inbox)*
- **PGP:** `0000 0000 0000 0000 0000  0000 0000 0000 0000 0000` *(replace and publish the key)*
- Include the affected component and version, the impact, and reproduction steps or a proof of concept.
- We acknowledge reports within **3 business days** and keep you updated through triage and fix.

## How we disclose what we find

1. **Discover.** The agent engine maps attack surface on targets we are authorised to test.
2. **Validate.** A researcher reproduces and triages every candidate before it is counted.
3. **Notify.** The vendor is contacted privately with details and a proof of concept.
4. **Remediate.** We default to a **90-day** window and extend it in good faith while a fix is in progress.
5. **Publish.** The CVE, the writeup (its research repository's README) and a minimal proof of concept
   go public once a fix ships or the agreed deadline passes.

Proofs of concept are scoped to verify the flaw and the fix. They are not turnkey exploitation tools.

## Good faith

We test only systems we are authorised to assess and avoid harm to users, data and availability.
We will not pursue action against researchers who report to us in the same spirit.

© BlackHalo · Georg Ph. E. Heise · Lufthansa Industry Solutions
