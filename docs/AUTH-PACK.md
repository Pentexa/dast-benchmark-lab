# 🔐 Vendor-Neutral Auth Pack (Identical Scan Conditions)

> Limma, ZAP, Burp ve Invicti'ye **aynı kimlik koşullarını** uygulamak için tek auth paketi.
> Araca özel betik yok — yalnızca standart HTTP kimlik bilgileri.

## Test kimlikleri (herkese açık demo hesapları)

| Kullanıcı | Şifre | Rol | Not |
|---|---|---|---|
| `alice` | `alice123` | user | Standart kurban-kullanıcı |
| `bob` | `bob123` | user | İkinci kullanıcı (IDOR/BOLA karşılaştırması) |
| `admin` | `admin123` | admin | Yükseltilmiş rol (zincir hedefi) |

Güvenlik sorusu cevabı (reset zinciri): `Pamuk` (tüm profillerde aynı — bilerek).

## Seviye 1 — Form login (tüm araçlar)

```
POST /app/api/login  Content-Type: application/json
{"username":"alice","password":"alice123"}
→ {"token":"<JWT>","user":"alice","role":"user"}
```

Sonraki isteklerde: `Authorization: Bearer <JWT>`

| Araç | Nasıl verilir? |
|---|---|
| ZAP | Context → Authentication (JSON-based) + Users (alice/bob/admin) → Forced User Mode |
| Burp | Project options → Sessions → cookie-jar + login macro (`/app/api/login`), ya da manuel `Authorization` header'ı |
| Nuclei | `-H "Authorization: Bearer <JWT>"` (login'den alınan token elle yapıştırılır) |
| Limma / Invicti | Scan policy → Authentication → custom header `Authorization: Bearer <JWT>` |

## Seviye 2 — Header/cookie kimlikleri (API senaryoları)

| Senaryo | Kimlik taşıma |
|---|---|
| `/api/users-secure/:id` | `X-User-Id: 1` (sahiplik: id ile eşleşmeli) |
| `/runtime/profile-mine` | `X-User-Id: 99` (BOLA: güvenilmemeli) |
| `/runtime/admin-export` | `X-Role: user` (BFLA: yetkisiz) |
| `/app/api/basket/add` (secure) | Önce `GET /app/api/csrf-token` (Bearer) → `csrf` cookie + `X-CSRF` header |
| `/app/api/feedback` | `X-Captcha: test123-captcha-bypass` (anahtar `/app/app.js` bundle yorumunda) |
| `/app/api/debug` | `X-Debug: 1` |
| `/authx/forgot`, `/cache/reset-link` | `X-Forwarded-Host: evil.com` (Host zehirlenmesi) |
| `/edge/panel`, `/edge/internal` | `X-Original-URL: /admin/users`, `X-Forwarded-For: 127.0.0.1` |

## Seviye 3 — Mod tanımları (scan.py --mode)

| Mod | Koşul | Kapsar |
|---|---|---|
| `unauthenticated` | Kimlik yok | Herkese açık yüzey (Seviye 1-2'nin bir kısmı) |
| `authenticated-full` | Seviye 1 + 2 tamamı | Auth-gated API, BOLA/IDOR, `/app` zincirleri |
| `advanced-protocol` | Üstü + WS/SSE/gRPC-Web + OOB dinleme + AJAX spider | Kör, zaman-tabanlı, race, SPA |

Karşılaştırma yaparken **aynı mod + aynı seed** kullanın:

```powershell
python evaluation/scan.py start --scanner "Arac Adı" --mode authenticated-full --reset --seed 7
# ... tara ...
python evaluation/scan.py finish --findings rapor --format <fmt>
```

## Notlar

- Token'lar 12 saat geçerli (`expiresIn: 12h`) — uzun taramalarda yenileme gerekmez.
- `/authx/otp`, `/api/otp-verify` kilitsiz akışlar için kod gerekmez (herhangi bir kod + davranış farkı ölçülür).
- Blind modda (`DAST_MODE=blind`) kimlik bilgileri değişmez; yalnızca cevap anahtarı gizlenir.
