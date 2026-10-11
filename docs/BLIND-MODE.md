# 🙈 Blind Mode (Fair Measurement)

> Transparent mode teaches; **blind mode measures**. Enable it when a scanner score must be fair.

## Enabling

```powershell
# Windows
$env:DAST_MODE="blind"; npm start
# macOS / Linux
DAST_MODE=blind npm start
```

Default is `transparent` (learning-friendly). The active mode is printed at startup and in `GET /api/overview` (`mode` field).

## What blind hides (leak surface)

| Surface | Transparent | Blind |
|---|---|---|
| `X-Vuln-Id` / `X-Vuln-Category` / `X-Ground-Truth` headers | present | **stripped on every response** (incl. 404/errors, so absence can't be an oracle) |
| Dashboard | expectation + vuln type + try-it links + payload cheat-sheet | **method + path only** + blind notice |
| `GET /api/ground-truth` | full GT (incl. `test_hint`) | **404** |
| `GET /api/overview` | vulnerable/secure/fp-trap split + verified count | **total + recorded scans only** |
| `GET /app/coverage` | hit/miss per endpoint with expectation | **404** |
| `logs/requests.log` | `vulnId`/`groundTruth` per request | **null** (signals still logged — behavior, not answers) |

Paths and `test_hint`-free discovery stay visible: a scanner must crawl, but nothing tells it **which endpoint is vulnerable**.

## Rules

1. **GT isolation:** in blind mode the server never needs GT answers; `ground-truth.json` is read only by `evaluation/*.py`. Treat the file as evaluator-private.
2. **Uniform silence:** headers are stripped everywhere, not just on vulnerable routes — a missing header must never discriminate.
3. **Same conditions:** always combine blind with reset+seed (`scan.py start --reset --seed 7`) so runs are comparable.
4. **Verify in transparent:** `verify.py` needs markers — run proofs in transparent, score scanners in blind.

## Checking blindness

```powershell
python tests/acceptance.py --target http://localhost:3000   # B3 asserts run per reported mode
```

B3 fails if any leak exists. See also [RESET.md](./RESET.md) and [ORACLES.md](./ORACLES.md).
