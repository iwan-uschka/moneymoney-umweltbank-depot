# MoneyMoney Umweltbank Depot — project notes

Single-file MoneyMoney WebBanking extension (`UmweltbankDepot.lua`, Lua 5.3+).
Syntax check: `luac -p UmweltbankDepot.lua`. There is no automated test; real
verification requires a live sync in MoneyMoney with an Umweltbank account.

## Umweltbank gateway behavior (probed 2026-07-07, unauthenticated)

An F5 BIG-IP **with ASM (web application firewall)** fronts the API. It
statefully validates cookies and headers, so responses depend on more than the
URL. Observed on
`GET /services_cloud/portal/proxy-gateway/serviceproxy/konto-service/v2/konto/group`:

- No session / bad `Authorization: Bearer` / empty-value cookies → **401**
  (JSON error body).
- Any **single header line over ~8192 bytes** → **400 "Bad Request"**
  (per header line, not per request; 2×4.5 KB headers pass).
- A **garbage TS cookie value** (`TS01fdfca9=garbage`) → **200 with the ASM
  "Request Rejected … support ID" HTML block page**. Never call
  `connection:setCookie` against this host — corrupting F5 TS cookie state
  changes ASM verdicts unpredictably.
- **The 400 on konto/group is intermittent and NOT code-related — proven
  2026-07-08:** commits 9e0ee04 and b9d3257 have byte-identical
  `UmweltbankDepot.lua` (only README differs), yet one run worked and one got
  400. All earlier per-commit attributions were sampling noise, compounded by
  extension caching (below).
- **Instrumented traces 2026-07-08/09 — what is proven:**
  - Cookie header at konto/group was only 573 bytes on a failing run — the
    header-size theory is dead.
  - `portal/login?code=…` serves only the **SPA HTML shell** (sets no tokens,
    does not consume the code); the real browser's SPA exchanges the code
    **client-side** via an XHR `POST oauth/token` (grant_type=
    authorization_code, client_id=online-banking, no secret).
  - The `access_token` HttpOnly cookie (~34-byte opaque value) is what
    authenticates the proxy-gateway: without it konto/group is a
    deterministic **401**; with it, mostly 200 but intermittently **400**.
  - The token response JSON carries only session metadata (`expires_in:89`,
    `sessionExpiresInSeconds:299`) — tokens come as Set-Cookie. The token
    response also drops the `vp-portal-session` cookie; a browser hitting the
    same endpoint gets the same Set-Cookie, so that is normal, not the bug.
  - **The cause of the intermittent 400 with valid tokens is still open.**
    Ruled out so far: header size, setCookie side effects, missing SPA-shell
    load (a run with shell + SPA-order token exchange still 400'd, 2026-07-09).
    Suspects: (1) SPA request headers on data calls — extension sent NONE
    (connection:get drops headers); since 2026-07-09 the data calls go through
    connection:request with Accept/X-VP-App-Locale/Referer, and the first run
    with those headers succeeded. Not yet proven (single run; earlier theories
    also had one-off successes) — needs a multi-day soak before the
    diagnostics come out. (2) SPA bootstrap XHRs between token exchange and
    data calls; (3) backend node/version skew behind the F5. If the 400 ever
    returns despite headers, capture the real browser's konto/group request
    headers via DevTools and diff against the extension's.
- The QR status endpoint's JSON includes a server-suggested poll interval
  (`{"state":"RETRY","interval":500}` — milliseconds; `-1` once approved).
- If the 400 ever returns, re-instrument with read-only prints: a
  pcall-wrapped helper that logs `connection:getCookies()` NAMES and SIZES
  (never values) before each post-scan request — no setCookie, no header
  changes.
- Data calls are deliberately kept wire-identical to the cookie-only flow
  (`connection:get`, whose headers argument is silently ignored). A variant
  sending `X-VP-App-Locale`/`Authorization` via `connection:request` plus
  `setCookie` pruning was tried 2026-07-07 and withdrawn.
- Cookies are path-scoped: CAS/auth cookies live under `/services_auth/*`,
  portal token cookies under `/services_cloud/portal*`. The data endpoints
  receive the `/services_cloud/portal*` + `/` cookie population.
- **MoneyMoney may keep serving a cached copy of the extension after the
  `.lua` file is replaced** (observed 2026-07-08 while A/B-testing versions).
  Always restart MoneyMoney before judging which version a test exercised.

## MoneyMoney Lua API gotchas (verified against moneymoney.app/api/webbanking)

- `Connection:get(url)` and `Connection:post(url, content, type)` take **no
  headers argument**. Custom headers only work via
  `Connection:request(method, url, postContent, postContentType, headers)`.
- Cookie storage is per-script-execution and shared by all Connections in the
  script; it is deleted when the script finishes. `connection:getCookies()`
  returns the `Cookie` header for the current URL; `connection:setCookie(...)`
  takes `Set-Cookie` syntax (but see the ASM warning above).
- Security table fields: WKN is `securityNumber`, exchange name is `market`,
  quantity currency is `currencyOfQuantity` (nil for share counts). Unknown
  fields are silently ignored — misspelled fields fail without any error.
- The `poll = true` challenge flag used by InitializeSession2 is undocumented;
  MoneyMoney fixes the poll tick and offers no interval control. (A 2×-per-tick
  status check via `MM.sleep(1)` was tried 2026-07-08 and reverted the next
  day at the user's request.)
- `MM.sleep(seconds)` exists; there is no documented timeout on how long an
  extension call may run, but long loops delay dialog cancellation — keep
  in-call polling short.
