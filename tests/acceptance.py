#!/usr/bin/env python3
"""V2 acceptance suite (fast, <60s). Full proof run is evaluation/verify.py.

Static checks (no server):
  A1 GT schema: unique ids, difficulty/oracle/execution present on every row
  A2 Manifest parity: fphell-manifest.json count == FP-HELL GT rows
  A3 Evaluator parity: ornek-bulgular scores match known values (no regression)

Live checks (--target, needs running server):
  B1 Reset endpoint works (loopback) and reports handlers>0
  B2 Spot proofs: a few P0/P1/P2 endpoints behave as GT claims
  B3 Mode honesty: transparent shows headers, blind hides everything
     (blind asserts run only when server reports mode=blind)

Usage:
  python tests/acceptance.py [--target http://localhost:3000]
"""
import json, os, sys, argparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "evaluation"))
from evaluate import load_gt, load_findings, compute_metrics

FAIL = []


def check(name, cond, detail=""):
    print(f"  [{'OK' if cond else 'FAIL'}] {name} {detail}")
    if not cond:
        FAIL.append(name)


def http(target, method, path, headers=None, body=None):
    url = target.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = Request(url, data=data, headers={"Content-Type": "application/json", **(headers or {})}, method=method)

    class NoRedir(__import__("urllib.request", fromlist=["HTTPRedirectHandler"]).HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    try:
        with __import__("urllib.request", fromlist=["build_opener"]).build_opener(NoRedir).open(req, timeout=15) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, {}, ""
    except Exception as e:
        return -1, {}, f"CONN: {e}"


def static_checks():
    print("== A static ==")
    gt = load_gt()
    ids = [g["id"] for g in gt]
    check("A1 unique ids", len(ids) == len(set(ids)), f"({len(ids)} rows)")
    bad = [g["id"] for g in gt if not g.get("difficulty") or "oracle" not in g or "execution" not in g]
    check("A1 schema fields", not bad, f"missing={bad[:5]}")
    vulns = [g for g in gt if g["expectation"] == "vulnerable"]
    no_oracle = [g["id"] for g in vulns if not g.get("oracle")]
    check("A1 every vuln has oracle", not no_oracle, f"gaps={no_oracle[:5]}")

    man = json.load(open(os.path.join(BASE, "routes", "fphell-manifest.json"), encoding="utf-8"))
    hell = [g for g in gt if g["id"].startswith("FP-HELL-")]
    check("A2 manifest parity", len(man) == len(hell), f"manifest={len(man)} gt={len(hell)}")

    f = load_findings(os.path.join(BASE, "evaluation", "ornek-bulgular.json"), "generic")
    m = compute_metrics(f, gt)
    check("A3 evaluator parity", (m["TP"], m["FP"], m["FN"], m["TN"]) == (2, 2, 192, 187),
          f"TP={m['TP']} FP={m['FP']} FN={m['FN']} TN={m['TN']}")
    return gt


def live_checks(target, gt):
    print(f"== B live ({target}) ==")
    st, _, _ = http(target, "GET", "/dashboard")
    if st == -1:
        print("  [SKIP] server unreachable — live checks skipped")
        return
    st, _, body = http(target, "POST", "/api/admin/reset", body={"seed": 7})
    try:
        rj = json.loads(body)
        check("B1 reset works", st == 200 and rj.get("reset_handlers", 0) > 0, body[:100])
    except Exception:
        check("B1 reset works", False, f"status={st}")

    # spot proofs (vuln)
    st, _, b = http(target, "GET", "/spa2/wizard?step=3&progress=2")
    check("B2 P1 wizard skip", "shipped without payment" in b)
    st, _, b = http(target, "POST", "/race2/claim?burst=10", body={"user": "acc"})
    check("B2 P1 race over-claim", "OVER-CLAIMED" in b)
    st, _, b = http(target, "GET", "/tenant/docs?tenant=globex&id=G9", headers={"X-Tenant": "acme"})
    check("B2 P1 tenant idor", "GLOBEX-SECRET-999" in b)
    # spot decoy (safe)
    st, _, b = http(target, "GET", "/fphell/sql-01?nick=<script>alert(9)</script>")
    check("B2 P2 decoy neutral", st == 200 and "<script>alert" not in b and "güvenli sayfa (decoy)" in b)

    # mode honesty
    st, _, body = http(target, "GET", "/api/overview")
    try:
        mode = json.loads(body).get("mode", "?")
    except Exception:
        mode = "?"
    st, rh, _ = http(target, "GET", "/xss/reflected?name=t")
    has_hdr = "X-Vuln-Id" in rh or "X-Ground-Truth" in rh
    if mode == "blind":
        check("B3 blind: no GT headers", not has_hdr)
        st, _, _ = http(target, "GET", "/api/ground-truth")
        check("B3 blind: GT api closed", st == 404, f"status={st}")
        st, _, b = http(target, "GET", "/dashboard")
        check("B3 blind: dashboard neutral", "ZAFAYETL" not in b and "Hızlı test" not in b)
    else:
        check("B3 transparent: headers present (sanity)", has_hdr,
              f"mode={mode} (restart with DAST_MODE=blind for blind asserts)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=os.environ.get("DAST_TARGET", "http://localhost:3000"))
    args = ap.parse_args()
    gt = static_checks()
    live_checks(args.target, gt)
    print(f"\n=== ACCEPTANCE: {'PASS' if not FAIL else 'FAIL: ' + str(FAIL)} ===")
    sys.exit(0 if not FAIL else 1)


if __name__ == "__main__":
    main()
