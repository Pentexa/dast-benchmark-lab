#!/usr/bin/env python3
"""P1 extension: append Extreme Range V2 ground-truth rows (id-uniqueness guarded).

Usage: python evaluation/extend_gt_p1.py [--apply]
"""
import json, os, sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GT_PATH = os.path.join(BASE, "ground-truth.json")
APPLY = "--apply" in sys.argv


def O(*matchers):
    """body-matcher oracle shorthand."""
    return {"source": "verify", "checks": [{"location": "body", "matcher": m} for m in matchers]}


def H(name, sub):
    return {"source": "verify", "checks": [{"location": "header", "header": name, "matcher": sub}]}


def S(code):
    return {"source": "verify", "checks": [{"location": "status", "matcher": str(code)}]}


ROWS = [
    # ---- P1.1 deep SPA ----
    {"id": "SPA2-SHADOW-01", "method": "GET", "path": "/spa2/widget", "category": "Client-Side", "vuln_type": "Shadow-DOM XSS (config JSON sink)", "expectation": "vulnerable", "test_hint": "/spa2/widget?config={\"html\":\"<img src=x onerror=alert(1)>\"}", "severity": "high", "difficulty": "hard", "oracle": O("<img src=x onerror=alert(1)>")},
    {"id": "SPA2-SHADOW-01-SECURE", "method": "GET", "path": "/spa2/widget-secure", "category": "Client-Side", "vuln_type": "Shadow-DOM allowlist control", "expectation": "secure", "test_hint": "/spa2/widget-secure?config=yildiz", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "SPA2-WIZARD-01", "method": "GET", "path": "/spa2/wizard", "category": "Client-Side", "vuln_type": "Multi-step wizard skip (unsigned progress)", "expectation": "vulnerable", "test_hint": "/spa2/wizard?step=3&progress=2", "severity": "medium", "difficulty": "hard", "oracle": O("shipped without payment")},
    {"id": "SPA2-WIZARD-01-SECURE", "method": "GET", "path": "/spa2/wizard-secure", "category": "Client-Side", "vuln_type": "HMAC-signed wizard control", "expectation": "secure", "test_hint": "/spa2/wizard-secure?step=3&progress=2.x", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.2 cross-role XSS ----
    {"id": "XSS2-STORED-ROLE-01", "method": "POST", "path": "/xss2/post", "category": "A03-XSS", "vuln_type": "Cross-role stored XSS entry (user writes)", "expectation": "vulnerable", "test_hint": "/xss2/post {user:x, message:<script>} then /xss2/view?id=N&as=admin", "severity": "high", "difficulty": "hard", "oracle": {"source": "verify-custom", "checks": [{"location": "body", "matcher": "raw script in admin view", "note": "post then view"}]}},
    {"id": "XSS2-STORED-ROLE-02", "method": "GET", "path": "/xss2/view", "category": "A03-XSS", "vuln_type": "Cross-role stored XSS trigger (admin reads raw)", "expectation": "vulnerable", "test_hint": "/xss2/view?id=<id>&as=admin", "severity": "high", "difficulty": "hard", "oracle": {"source": "verify-custom", "checks": [{"location": "body", "matcher": "raw script in admin view", "note": "post then view"}]}},
    {"id": "XSS2-STORED-ROLE-01-SECURE", "method": "GET", "path": "/xss2/view-secure", "category": "A03-XSS", "vuln_type": "Escaped admin view control", "expectation": "secure", "test_hint": "/xss2/view-secure?id=1", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "XSS2-BLIND-ROLE-01", "method": "POST", "path": "/xss2/blindreply", "category": "A03-XSS", "vuln_type": "Blind mod-queue entry (callback stored)", "expectation": "vulnerable", "test_hint": "/xss2/blindreply {callback:/oob/x}", "severity": "high", "difficulty": "chaos", "oracle": {"source": "verify-custom", "checks": [{"location": "body", "matcher": "script src callback in mod view", "note": "post then modqueue"}]}},
    {"id": "XSS2-BLIND-ROLE-02", "method": "GET", "path": "/xss2/modqueue", "category": "A03-XSS", "vuln_type": "Blind mod-queue trigger (script src)", "expectation": "vulnerable", "test_hint": "/xss2/modqueue?role=moderator", "severity": "high", "difficulty": "chaos", "oracle": {"source": "verify-custom", "checks": [{"location": "body", "matcher": '<script src="/oob/', "note": "post then modqueue"}]}},
    {"id": "XSS2-BLIND-ROLE-01-SECURE", "method": "GET", "path": "/xss2/modqueue-secure", "category": "A03-XSS", "vuln_type": "Callback allowlist control", "expectation": "secure", "test_hint": "/xss2/modqueue-secure?role=moderator", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.3 multi-tenant ----
    {"id": "TENANT-IDOR-01", "method": "GET", "path": "/tenant/docs", "category": "A01-AccessControl", "vuln_type": "Cross-tenant document read (no ownership)", "expectation": "vulnerable", "test_hint": "/tenant/docs?tenant=globex&id=G9 (X-Tenant: acme)", "severity": "high", "difficulty": "hard", "oracle": O("GLOBEX-SECRET-999")},
    {"id": "TENANT-IDOR-01-SECURE", "method": "GET", "path": "/tenant/docs-secure", "category": "A01-AccessControl", "vuln_type": "Tenant+owner control", "expectation": "secure", "test_hint": "/tenant/docs-secure?tenant=acme&id=D1 (X-Tenant/X-User)", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "TENANT-BOLA-01", "method": "POST", "path": "/tenant/transfer", "category": "A01-AccessControl", "vuln_type": "Cross-tenant write without authz", "expectation": "vulnerable", "test_hint": "/tenant/transfer {docId:D1, toTenant:globex}", "severity": "high", "difficulty": "hard", "oracle": O("moved", "globex")},
    {"id": "TENANT-BOLA-01-SECURE", "method": "POST", "path": "/tenant/transfer-secure", "category": "A01-AccessControl", "vuln_type": "Admin-only transfer control", "expectation": "secure", "test_hint": "/tenant/transfer-secure (X-Role: admin)", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.4 GraphQL nested/federation ----
    {"id": "GQL2-NESTED-01", "method": "POST", "path": "/gql2/graphql", "category": "API-GraphQL", "vuln_type": "Nested field authz leak (supplierCost)", "expectation": "vulnerable", "test_hint": "/gql2/graphql {user { orders { supplierCost } }}", "severity": "high", "difficulty": "hard", "oracle": O("supplierCost", "42.5")},
    {"id": "GQL2-NESTED-01-SECURE", "method": "POST", "path": "/gql2/graphql-secure", "category": "API-GraphQL", "vuln_type": "Field-level redaction control", "expectation": "secure", "test_hint": "/gql2/graphql-secure supplierCost (no role)", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "GQL2-FED-01", "method": "POST", "path": "/gql2/federation", "category": "API-GraphQL", "vuln_type": "Unsigned federation entity passthrough (SSN)", "expectation": "vulnerable", "test_hint": "/gql2/federation {_entities:[{__typename:User}]}", "severity": "high", "difficulty": "hard", "oracle": O("422-11-0001")},
    {"id": "GQL2-FED-01-SECURE", "method": "POST", "path": "/gql2/federation-secure", "category": "API-GraphQL", "vuln_type": "Gateway signature control", "expectation": "secure", "test_hint": "/gql2/federation-secure (no sig -> 401)", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.5 OIDC ----
    {"id": "OIDC-REDIR-01", "method": "GET", "path": "/oidc/authorize", "category": "A07-Auth", "vuln_type": "OAuth redirect_uri not validated (code theft)", "expectation": "vulnerable", "test_hint": "/oidc/authorize?client_id=x&redirect_uri=https://evil.com/cb&response_type=code", "severity": "high", "difficulty": "hard", "oracle": H("Location", "evil.com")},
    {"id": "OIDC-NOSTATE-01", "method": "GET", "path": "/oidc/authorize-nostate", "category": "A07-Auth", "vuln_type": "Stateless flow (connect-CSRF)", "expectation": "vulnerable", "test_hint": "/oidc/authorize-nostate?redirect_uri=https://evil.com/cb", "severity": "medium", "difficulty": "hard", "oracle": H("Location", "evil.com")},
    {"id": "OIDC-REDIR-01-SECURE", "method": "GET", "path": "/oidc/authorize-secure", "category": "A07-Auth", "vuln_type": "Allowlist+state control", "expectation": "secure", "test_hint": "/oidc/authorize-secure?redirect_uri=https://evil.com -> 400", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "OIDC-PKCE-01", "method": "POST", "path": "/oidc/token", "category": "A07-Auth", "vuln_type": "Public client without PKCE accepted", "expectation": "vulnerable", "test_hint": "/oidc/token {code:AUTHCODE-x} (no verifier)", "severity": "high", "difficulty": "hard", "oracle": {"source": "verify-custom", "checks": [{"location": "body", "matcher": "mock-at-", "note": "needs fresh code from authorize"}]}},
    {"id": "OIDC-PKCE-01-SECURE", "method": "POST", "path": "/oidc/token-secure", "category": "A07-Auth", "vuln_type": "Verifier-required control", "expectation": "secure", "test_hint": "/oidc/token-secure (no verifier -> 400)", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.6 workflow ----
    {"id": "FLOW-ORDER-01", "method": "POST", "path": "/flow/orders", "category": "A04-BusinessLogic", "vuln_type": "Order creation (chain start)", "expectation": "vulnerable", "test_hint": "/flow/orders {item:tshirt}", "severity": "low", "difficulty": "medium", "oracle": O("FL-")},
    {"id": "FLOW-SKIP-01", "method": "POST", "path": "/flow/ship", "category": "A04-BusinessLogic", "vuln_type": "Ship without payment (step skip)", "expectation": "vulnerable", "test_hint": "/flow/ship {orderId:FL-1001}", "severity": "high", "difficulty": "chaos", "oracle": O("shipped without payment")},
    {"id": "FLOW-SKIP-01-SECURE", "method": "POST", "path": "/flow/ship-secure", "category": "A04-BusinessLogic", "vuln_type": "Paid-state gate control", "expectation": "secure", "test_hint": "/flow/ship-secure {orderId:FL-1001} -> 409", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "FLOW-REPLAY-01", "method": "POST", "path": "/flow/pay", "category": "A04-BusinessLogic", "vuln_type": "Double charge replay (no idempotency)", "expectation": "vulnerable", "test_hint": "/flow/pay {orderId:FL-1002}", "severity": "medium", "difficulty": "hard", "oracle": O("charged twice")},
    {"id": "FLOW-REPLAY-01-SECURE", "method": "POST", "path": "/flow/pay-secure", "category": "A04-BusinessLogic", "vuln_type": "Idempotency control", "expectation": "secure", "test_hint": "/flow/pay-secure {orderId:FL-1002} -> 409", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.7 deterministic race ----
    {"id": "RACE2-BURST-01", "method": "POST", "path": "/race2/claim", "category": "A04-BusinessLogic", "vuln_type": "Non-atomic burst claim (over-claim)", "expectation": "vulnerable", "test_hint": "/race2/claim?burst=10 {user:x}", "severity": "medium", "difficulty": "chaos", "oracle": O("OVER-CLAIMED")},
    {"id": "RACE2-BURST-01-SECURE", "method": "POST", "path": "/race2/claim-secure", "category": "A04-BusinessLogic", "vuln_type": "Atomic counter control", "expectation": "secure", "test_hint": "/race2/claim-secure?burst=10 -> partial+waitlist", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.8 async second-order ----
    {"id": "ASYNC2-ENTRY-01", "method": "POST", "path": "/async2/submit", "category": "A03-Injection", "vuln_type": "Async second-order entry (queued raw)", "expectation": "vulnerable", "test_hint": "/async2/submit {username:x' OR '1'='1}", "severity": "medium", "difficulty": "hard", "oracle": O("queued")},
    {"id": "ASYNC2-TRIGGER-01", "method": "POST", "path": "/async2/flush", "category": "A03-Injection", "vuln_type": "Async worker trigger (string concat)", "expectation": "vulnerable", "test_hint": "POST /async2/flush after submit", "severity": "high", "difficulty": "chaos", "oracle": {"source": "verify-custom", "checks": [{"location": "body", "matcher": "2 rows dumped", "note": "submit evil then flush then report"}]}},
    {"id": "ASYNC2-ENTRY-01-SECURE", "method": "POST", "path": "/async2/submit-secure", "category": "A03-Injection", "vuln_type": "Allowlist entry control", "expectation": "secure", "test_hint": "/async2/submit-secure {username:x' OR...} -> 400", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "ASYNC2-TRIGGER-01-SECURE", "method": "POST", "path": "/async2/flush-secure", "category": "A03-Injection", "vuln_type": "Parameterized worker control", "expectation": "secure", "test_hint": "POST /async2/flush-secure", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.9 blind timing ----
    {"id": "BLINDTIME-01", "method": "GET", "path": "/blindtime/lookup", "category": "A03-Injection", "vuln_type": "Calibrated blind timing (SLEEP oracle)", "expectation": "vulnerable", "test_hint": "/blindtime/lookup?key=SLEEP(2) (calibrate: /blindtime/calibrate)", "severity": "high", "difficulty": "chaos", "oracle": {"source": "verify-custom", "checks": [{"location": "timing", "matcher": "delta>=1500ms vs calibrate", "note": "jitter-budgeted delay oracle"}]}},
    {"id": "BLINDTIME-01-SECURE", "method": "GET", "path": "/blindtime/lookup-secure", "category": "A03-Injection", "vuln_type": "Constant-time lookup control", "expectation": "secure", "test_hint": "/blindtime/lookup-secure?key=SLEEP(2)", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.10 staged OOB ----
    {"id": "OOB2-STAGED-01", "method": "POST", "path": "/oob2/register", "category": "A03-XSS", "vuln_type": "Staged OOB entry (callback accepted)", "expectation": "vulnerable", "test_hint": "/oob2/register {callback:/oob/x} then /oob2/fire?token=", "severity": "high", "difficulty": "chaos", "oracle": {"source": "verify-custom", "checks": [{"location": "oob", "matcher": "stage2-fired counter delta", "note": "register then fire then oob-hits"}]}},
    {"id": "OOB2-STAGED-01-SECURE", "method": "POST", "path": "/oob2/register-secure", "category": "A03-XSS", "vuln_type": "External callback denied control", "expectation": "secure", "test_hint": "/oob2/register-secure -> 403", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.11 parser differentials ----
    {"id": "PARSER-SEMI-01", "method": "GET", "path": "/parser/semicolon", "category": "A03-Injection", "vuln_type": "Semicolon separator first-wins (smuggling)", "expectation": "vulnerable", "test_hint": "/parser/semicolon?x=1;x=2", "severity": "medium", "difficulty": "hard", "oracle": O("parsed_first: 1")},
    {"id": "PARSER-CTYPE-01", "method": "POST", "path": "/parser/ctype", "category": "A03-Injection", "vuln_type": "Content-type fallback parser escalation", "expectation": "vulnerable", "test_hint": "/parser/ctype (JSON ct + form body admin=true)", "severity": "high", "difficulty": "hard", "oracle": O("fallback parser")},
    {"id": "PARSER-CTYPE-01-SECURE", "method": "POST", "path": "/parser/ctype-secure", "category": "A03-Injection", "vuln_type": "Strict frame control", "expectation": "secure", "test_hint": "/parser/ctype-secure (form body -> 400)", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "PARSER-METHOD-01", "method": "GET", "path": "/parser/resource", "category": "A01-AccessControl", "vuln_type": "Query _method DELETE (verb confusion)", "expectation": "vulnerable", "test_hint": "/parser/resource?_method=DELETE", "severity": "medium", "difficulty": "medium", "oracle": O("SİLİNDİ")},
    {"id": "PARSER-METHOD-01-SECURE", "method": "GET", "path": "/parser/resource-secure", "category": "A01-AccessControl", "vuln_type": "_method ignored control", "expectation": "secure", "test_hint": "/parser/resource-secure?_method=DELETE", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.12 shared cache ----
    {"id": "CACHE2-SHARED-01", "method": "GET", "path": "/cache2/profile", "category": "A05-CacheSmuggle", "vuln_type": "Shared cache ignores identity (PII cross-user)", "expectation": "vulnerable", "test_hint": "/cache2/profile?user=1 then same URL as bob", "severity": "high", "difficulty": "chaos", "oracle": {"source": "verify-custom", "checks": [{"location": "header+body", "matcher": "X-Cache: HIT + other user TCKN", "note": "poison as alice, read as bob"}]}},
    {"id": "CACHE2-SHARED-01-SECURE", "method": "GET", "path": "/cache2/profile-secure", "category": "A05-CacheSmuggle", "vuln_type": "Private+Vary control", "expectation": "secure", "test_hint": "/cache2/profile-secure?user=1", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "CACHE2-POISON-01", "method": "GET", "path": "/cache2/search", "category": "A05-CacheSmuggle", "vuln_type": "Cached reflection serves XSS to others", "expectation": "vulnerable", "test_hint": "/cache2/search?q=<script>alert(9)</script>", "severity": "high", "difficulty": "hard", "oracle": {"source": "verify-custom", "checks": [{"location": "body", "matcher": "cached reflection HIT", "note": "request twice, second is HIT"}]}},
    {"id": "CACHE2-POISON-01-SECURE", "method": "GET", "path": "/cache2/search-secure", "category": "A05-CacheSmuggle", "vuln_type": "No-store escaped control", "expectation": "secure", "test_hint": "/cache2/search-secure?q=<script>", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.13 confusion ----
    {"id": "CONFUSE-ENUM-01", "method": "GET", "path": "/confuse/user/:name", "category": "A01-AccessControl", "vuln_type": "Soft-404 user enumeration oracle", "expectation": "vulnerable", "test_hint": "/confuse/user/zzznonexist (200 + hint)", "severity": "medium", "difficulty": "hard", "oracle": O("did you mean")},
    {"id": "CONFUSE-ENUM-01-SECURE", "method": "GET", "path": "/confuse/user-secure/:name", "category": "A01-AccessControl", "vuln_type": "Real 404 control", "expectation": "secure", "test_hint": "/confuse/user-secure/zzz -> 404", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "CONFUSE-RATELIMIT-01", "method": "GET", "path": "/confuse/ratelimit", "category": "A07-Auth", "vuln_type": "Announced but unenforced limit", "expectation": "vulnerable", "test_hint": "/confuse/ratelimit (headers lie)", "severity": "medium", "difficulty": "medium", "oracle": O("not enforced")},
    {"id": "CONFUSE-RATELIMIT-01-SECURE", "method": "GET", "path": "/confuse/ratelimit-secure", "category": "A07-Auth", "vuln_type": "Enforced limit control", "expectation": "secure", "test_hint": "/confuse/ratelimit-secure x6 -> 429", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    # ---- P1.14 realtime ----
    {"id": "REALTIME-WS-01", "method": "GET", "path": "/realtime/ws", "category": "Client-Side", "vuln_type": "WebSocket no origin check (hijackable echo)", "expectation": "vulnerable", "test_hint": "WS /realtime/ws (any Origin accepted)", "severity": "high", "difficulty": "hard", "oracle": {"source": "verify-custom", "checks": [{"location": "websocket", "matcher": "WS-ECHO-READY + echo", "note": "raw-socket upgrade"}]}},
    {"id": "REALTIME-WS-01-SECURE", "method": "GET", "path": "/realtime/ws-secure", "category": "Client-Side", "vuln_type": "Origin allowlist WS control", "expectation": "secure", "test_hint": "WS /realtime/ws-secure (evil Origin -> close)", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "REALTIME-SSE-01", "method": "GET", "path": "/realtime/sse", "category": "Client-Side", "vuln_type": "SSE raw reflection", "expectation": "vulnerable", "test_hint": "/realtime/sse?msg=<script>alert(1)</script>", "severity": "medium", "difficulty": "hard", "oracle": O("<script>alert(1)</script>")},
    {"id": "REALTIME-SSE-01-SECURE", "method": "GET", "path": "/realtime/sse-secure", "category": "Client-Side", "vuln_type": "Escaped SSE control", "expectation": "secure", "test_hint": "/realtime/sse-secure?msg=<script>", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
    {"id": "REALTIME-GRPC-01", "method": "POST", "path": "/realtime/grpc", "category": "API-GraphQL", "vuln_type": "gRPC-Web verbose error (stack+internals)", "expectation": "vulnerable", "test_hint": "POST /realtime/grpc (bad frame)", "severity": "medium", "difficulty": "medium", "oracle": O("parseFrame", "trace=")},
    {"id": "REALTIME-GRPC-01-SECURE", "method": "POST", "path": "/realtime/grpc-secure", "category": "API-GraphQL", "vuln_type": "Minimal error control", "expectation": "secure", "test_hint": "POST /realtime/grpc-secure", "severity": "info", "difficulty": "fp-hunter", "oracle": None},
]


def main():
    gt = json.load(open(GT_PATH, encoding="utf-8"))
    have = {g["id"] for g in gt}
    dup = [r["id"] for r in ROWS if r["id"] in have]
    if dup:
        print(f"DUPLICATE IDS (aborted): {dup}")
        sys.exit(1)
    from collections import Counter
    print(f"current: {len(gt)} rows; adding: {len(ROWS)}")
    print("new by difficulty:", dict(Counter(r["difficulty"] for r in ROWS)))
    print("new vulnerable:", sum(1 for r in ROWS if r["expectation"] == "vulnerable"))
    if APPLY:
        gt.extend(ROWS)
        json.dump(gt, open(GT_PATH, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"applied: {GT_PATH} -> {len(gt)} rows")
    else:
        print("dry-run (use --apply to write)")


if __name__ == "__main__":
    main()
