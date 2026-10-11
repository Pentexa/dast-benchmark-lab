# 🔄 Deterministic Resets & Seeds

> Identical scan conditions for every tool: reset state, fix the seed, then scan.

## Reset endpoint

```
POST /api/admin/reset  { "seed": 7 }
→ { ok, mode, seed, reset_handlers, errors, at }
```

- **Loopback only** (`127.0.0.1`/`::1`); if `DAST_ADMIN_TOKEN` is set, `X-Admin-Token` header is required.
- Calls all 20 registered handlers (`lib/stateReset.js`): OTP/lock counters, coupon pools, baskets/wallets/orders/points/giftcards, feedback queues, async queues, caches, parser store, OOB stages, login throttles, user-email restores.
- `seed` reseeds the deterministic PRNG (`lib/seeded.js`, mulberry32) used by all P1/P2 generated values.

## Recommended flow (identical conditions)

```powershell
python evaluation/scan.py start --scanner "ZAP 2.17" --mode authenticated-full --reset --seed 7
# ... run scanner ...
python evaluation/scan.py finish --findings zap.json --format zap
python evaluation/verify.py --seed 7   # optional: re-prove the range afterwards
```

`verify.py --seed` and `scan.py start --reset --seed` hit the same endpoint, so proofs and scans share conditions.

## Determinism scope (honest limits)

- ✅ Seeded: voucher pools, order counters, generated tokens/codes in P1/P2 code, resettable locks/queues.
- ⚠️ Legacy exceptions: `/oidc` codes use `Math.random`, CSRF tokens use `Math.random` — random per request but **never affect scoring** (proofs extract them dynamically).
- ✅ Reproducibility check: two `verify.py --seed 7` runs back-to-back produce identical pass/fail sets (timestamps除外 in `verification.json`).

## Files

| File | Role |
|---|---|
| `lib/stateReset.js` | handler registry (`onReset`/`resetAll`) |
| `lib/seeded.js` | seeded PRNG (`reseed/rand/randInt/pick/token`) |
| `lib/mode.js` | `isBlind()` gate |
| `evaluation/verify.py --seed` | prove after reset |
| `evaluation/scan.py start --reset --seed` | scan after reset |
