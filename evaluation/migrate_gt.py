#!/usr/bin/env python3
"""P0 migration: ground-truth.json -> v2 schema (adds difficulty + oracle, keeps all v1 fields).

- difficulty: easy | medium | hard | chaos | fp-hunter (secure + fp-trap -> fp-hunter)
- oracle: derived from evaluation/verify.py proof markers (P dict) + hand-mapped custom proofs.
  Vuln rows with no proof anywhere get oracle=null + needs_oracle=true (gap report).
- Original backed up to evaluation/ground-truth.v1.json (first run only).

Usage: python evaluation/migrate_gt.py [--apply]
  Without --apply: dry-run, prints distribution + gaps.
"""
import json, os, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_PATH = os.path.join(BASE, "ground-truth.json")
BACKUP = os.path.join(BASE, "evaluation", "ground-truth.v1.json")
APPLY = "--apply" in sys.argv

sys.path.insert(0, os.path.join(BASE, "evaluation"))
import verify as V

EASY = {
    "XSS-REFL-01", "INJ-SQLI-01", "INJ-AUTH-BYPASS-01", "INJ-CMDI-01", "INJ-CRLF-01",
    "AC-IDOR-01", "AC-TRAV-01", "AC-FORCED-01", "REDIR-01", "CSRF-01",
    "AUTH-JWT-01", "AUTH-RESET-01", "AUTH-BRUTE-01", "AUTH-SESS-01",
    "CRYPTO-PAN-01", "CRYPTO-DEBUG-01", "CRYPTO-GIT-01", "CRYPTO-HASH-01",
    "MIS-HDR-01", "MIS-ERR-01", "MIS-DIR-01", "MIS-DEFAULT-01", "CORS-01", "CLICK-01",
    "SSRF-01", "BIZ-01", "API-BOLA-01", "API-EXCESS-01", "API-KEY-01", "API-PAGE-01",
    "API-INVITE-01", "GQL-INTROS-01", "CL-JSONP-01", "CL-GOTO-01",
    "EXP-ENV-01", "EXP-BAK-01", "EXP-DS-01", "EXP-MAP-01", "EXP-SWAG-01", "EXP-ACT-01",
    "EXP-ROBOTS-01", "SHOP-PRICE-01", "SHOP-QTY-01", "SHOP-ORDER-01",
    "RT-HDRSQLI-01", "RT-HPP-01", "RT-MAGIC-01", "RT-PHPINFO-01", "RT-PKG-01",
    "RT-COMPOSER-01", "RT-COOKIE-01", "RT-SIDURL-01", "RT-RESETLEAK-01",
    "EDGE-XDOM-01", "EDGE-CFG-01", "EDGE-TRACE-01", "CH-LEGACY-01",
    "APP-TRACK-01", "APP-REG-01", "APP-SHIP-01", "AX-REMEMBER-01",
    "CL-PM-01", "INJ-NOSQLI-01", "RT-BOOL-01", "FILE-CSV-01",
}
HARD = {
    "XSS-STORED-01", "XSS-DOM-01", "XSS-MXSS-01", "CL-MD-01", "CL-CLOBBER-01",
    "CL-PPOLL-01", "CL-PPOLLQ-01", "INJ-SSTI-01", "INJ-LDAP-01", "INJ-XPATH-01",
    "INJ-XXE-01", "AUTHX-OTP-01", "AUTHX-MFA-01", "AUTHX-OAUTH-01",
    "AUTHX-RESET-POISON-01", "AUTHX-ENUM-01", "AUTHX-KID-01", "AUTHX-JKU-01",
    "AUTHX-WEAK-01", "GQL-BATCH-01", "GQL-IDOR-01", "API-MASS-01", "API-RATE-01",
    "APP-ADDR-01", "APP-BASKET-01", "APP-CSRF-01", "APP-WALLET-01", "APP-REFUND-01",
    "APP-BFLA-01", "APP-DEBUG-01", "APP-AVATAR-01", "APP-ENUM-01", "APP-TOKEN-01",
    "APP-RECOVERY-01", "APP-EMAIL-01", "APP-GIFT-01", "APP-POINTS-01",
    "CH-UNION-01", "CH-STACK-01", "CH-SSTI-JINJA", "CH-SSTI-TWIG", "CH-SSTI-FMT",
    "CH-SSTI-ERB", "CH-ROLE-01", "CH-HTACCESS-01", "CH-VERB-01",
    "RT-ORDERBY-01", "RT-HEADBOLA-01", "RT-BFLA-01", "RT-JWK-01", "RT-NOEXP-ISSUE",
    "RT-NOEXP-01", "RT-UPLDBL-01", "RT-CTX-ATTR-01", "RT-CTX-JS-01",
    "RT-REDIRBYPASS-01", "RT-MAILHDR-01", "RT-LOG4J-01",
    "EDGE-SSRF-DEC", "EDGE-SSRF-ZERO", "EDGE-SSRF-AT", "EDGE-SSRF-FRAG",
    "EDGE-SSRF-REDIR", "EDGE-RET-01", "EDGE-DOUBLE-01", "EDGE-ORIG-01", "EDGE-LOCAL-01",
    "FILE-SVG-01", "FILE-ZIP-01", "FILE-LFI-01", "FILE-RFI-01", "FILE-WRAP-01",
    "FILE-UNI-01", "CACHE-HOST-01", "CACHE-DECEPT-01", "HTTP-METHOD-01", "CACHE-XFF-01",
    "UPL-01", "DESER-01", "AX-REUSE-01", "AX-NOSTATE-01",
}
CHAOS = {
    "RT-TIME-01", "RT-BLINDXSS-01", "RT-BLINDXSS-02", "RT-LOGPOISON-01",
    "RT-CACHEPOISON-01", "CH-2ND-01", "CH-2ND-02", "HTTP-SMUG-01",
    "APP-FEED-01", "APP-FEEDVIEW-01", "APP-MASS-01", "APP-RESET-01", "APP-COUPON-01",
    "APP-AUTH-01", "SHOP-RACE-01", "GQL-DEPTH-01", "AX-CONFUSE-01",
}

# custom_proofs (multi-step) oracle approximations: id -> {location, matcher, note}
CUSTOM_ORACLES = {
    "XSS-STORED-01": {"location": "body", "matcher": "<img src=x onerror=alert(9)>", "note": "stored round-trip"},
    "CL-MD-01": {"location": "body", "matcher": "<svg onload=alert(9)>", "note": "markdown round-trip"},
    "RT-TIME-01": {"location": "timing", "matcher": ">=2500ms + body SLEEP", "note": "real delay oracle"},
    "RT-LOGPOISON-01": {"location": "body", "matcher": "dynamic:log-reflection", "note": "unique tag reflected in viewer"},
    "RT-NOEXP-01": {"location": "body", "matcher": "süresiz|Kabul", "note": "chain: issue-long then verify"},
    "RT-BLINDXSS-01": {"location": "oob", "matcher": "callback stored", "note": "blind entry"},
    "RT-BLINDXSS-02": {"location": "body", "matcher": '<script src="/oob/', "note": "admin view trigger"},
    "CH-2ND-02": {"location": "body", "matcher": "admin@example.com", "note": "second-order dump after register2"},
    "AUTHX-WEAK-01": {"location": "body", "matcher": "Kırıldı", "note": "weak secret cracked"},
    "AUTH-JWT-01": {"location": "body", "matcher": "doğrulamasız|attacker", "note": "alg:none accepted"},
    "AUTHX-KID-01": {"location": "body", "matcher": "dev.key", "note": "kid traversal"},
    "AUTHX-JKU-01": {"location": "body", "matcher": "allowlist dışı", "note": "jku bypass"},
    "RT-JWK-01": {"location": "body", "matcher": "Gömülü jwk", "note": "embedded jwk trusted"},
    "AX-CONFUSE-01": {"location": "body", "matcher": "GERÇEK KRİPTO", "note": "RS->HS with real HMAC(pubkey)"},
    "APP-FEEDVIEW-01": {"location": "body", "matcher": "<script>alert(9)</script>", "note": "chain: escalation then stored XSS trigger"},
    "HTTP-SMUG-01": {"location": "body", "matcher": "KABUL EDİLDİ", "note": "raw-socket chunked TE"},
    "APP-AUTH-01": {"location": "status-sequence", "matcher": "no 429 across 6 bad logins", "note": "lockout absent"},
}


def oracle_from_markers(markers):
    out = []
    for mk in markers:
        if mk.startswith("STATUS:"):
            out.append({"location": "status", "matcher": mk.split(":", 1)[1]})
        elif mk.startswith("HDR:"):
            _, name, sub = mk.split(":", 2)
            out.append({"location": "header", "header": name, "matcher": sub})
        elif mk.startswith("NOHDR:"):
            out.append({"location": "header-absent", "header": mk.split(":", 1)[1]})
        elif mk == "COOKIE-NOFLAG":
            out.append({"location": "cookie", "matcher": "Set-Cookie without HttpOnly"})
        else:
            out.append({"location": "body", "matcher": mk})
    return out


def main():
    gt = json.load(open(GT_PATH, encoding="utf-8"))
    P = V.P
    vuln_ids = {g["id"] for g in gt if g["expectation"] == "vulnerable"}
    print(f"GT rows: {len(gt)}, vulnerable: {len(vuln_ids)}, P proofs: {len(P)}")
    unknown_p = sorted(set(P) - {g["id"] for g in gt})
    print(f"P ids not in GT (stale?): {unknown_p}")

    gaps, unknown_diff = [], []
    for g in gt:
        gid = g["id"]
        exp = g["expectation"]
        if exp in ("secure", "fp-trap"):
            g["difficulty"] = "fp-hunter"
            g.setdefault("oracle", None)
            continue
        if gid in EASY:
            g["difficulty"] = "easy"
        elif gid in HARD:
            g["difficulty"] = "hard"
        elif gid in CHAOS:
            g["difficulty"] = "chaos"
        else:
            g["difficulty"] = "medium"
            unknown_diff.append(gid)
        if gid in P:
            g["oracle"] = {"source": "verify", "checks": oracle_from_markers(P[gid][5])}
        elif gid in CUSTOM_ORACLES:
            c = CUSTOM_ORACLES[gid]
            g["oracle"] = {"source": "verify-custom", "checks": [c]}
        else:
            g["oracle"] = None
            g["needs_oracle"] = True
            gaps.append(gid)

    from collections import Counter
    print("difficulty:", dict(Counter(g["difficulty"] for g in gt)))
    print(f"medium-by-default ({len(unknown_diff)}): {sorted(unknown_diff)}")
    print(f"vuln without oracle ({len(gaps)}): {sorted(gaps)}")

    if APPLY:
        if not os.path.exists(BACKUP):
            json.dump(json.load(open(GT_PATH, encoding="utf-8")), open(BACKUP, "w", encoding="utf-8"),
                      indent=2, ensure_ascii=False)
            print(f"backup: {BACKUP}")
        json.dump(gt, open(GT_PATH, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"applied: {GT_PATH}")
    else:
        print("dry-run (use --apply to write)")


if __name__ == "__main__":
    main()
