# Proof of concept — CVE-YYYY-NNNNN

Run this only against systems you own or are authorised to test.

## Requirements

- Vulnerable version: Vendor Product x.y.z (a Docker image or setup notes for a local instance)
- Python 3.11+ (or whatever the PoC needs)

## Usage

```bash
python3 exploit.py --target http://127.0.0.1:8080
```

## Expected result

What a successful run shows. Keep the PoC minimal: enough to verify the flaw and the fix.
