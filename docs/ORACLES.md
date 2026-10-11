# 🔮 Oracles & Verification Registry

> Every vulnerable row is provable; every decoy row is provably clean. This file defines how.

## Ground-truth row schema (v2)

```json
{
  "id": "INJ-SQLI-01", "method": "GET", "path": "/injection/sqli",
  "category": "A03-Injection", "vuln_type": "SQL Injection (error-based)",
  "expectation": "vulnerable", "test_hint": "/injection/sqli?id=1' OR '1'='1",
  "severity": "high",
  "difficulty": "easy | medium | hard | chaos | fp-hunter",
  "oracle": { "source": "verify | verify-custom", "checks": [
    { "location": "body | header | header-absent | status | cookie | timing | oob | websocket | status-sequence | header+body",
      "matcher": "substring / rule", "header": "Name?" }
  ]},
  "execution": "live | simulated | n/a"
}
```

- `difficulty` — which scanner capability catches it (see `docs/ZORLUK-SEVIYELERI.md`).
- `oracle.checks` — machine-readable proof contract; `verify.py` implements it.
- `execution` — **live** = server really performed it (slept, verified crypto, locked, cached, echoed, transitioned state); **simulated** = mock assertion with no backend (fake dumps/metadata/secrets); **n/a** = secure/decoy rows.
- `needs_oracle: true` — gap flag if a vuln ever lacks proof (currently **zero** gaps).
- Decoy rows additionally carry `negative_proof: {present: [...], absent: [...]}`.

## Proof sources

| Source | Where | Covers |
|---|---|---|
| `P` / `P1` dicts | `evaluation/verify.py` | Single-request proofs: 148 legacy + 21 P1 |
| `custom_proofs()` | `evaluation/verify.py` | Multi-step: stored XSS round-trips, chains, timing, OOB, crypto, WS socket, cache poisoning |
| Decoy negatives | `evaluation/verify.py` (P2 loop) | 104 decoys: trap text present + vuln markers absent |

## Running verification

```powershell
python evaluation/verify.py --seed 7        # resets server state first (deterministic)
python tests/acceptance.py                  # fast suite: schema + parity + spot checks
npm test                                     # same as above
```

Current gates: **194/194 exploitable, 104/104 decoys clean** (`evaluation/verification.json`).

## Matching (evaluator side)

`evaluate.compute_metrics()` supports two claim strengths:

- **strong** — finding carries `vuln_id` matching a GT id (direct row claim).
- **weak** — path fallback (legacy behavior, all old reports work unchanged).

Reports (`report.py`) show the split, so vuln-level precision is auditable.
