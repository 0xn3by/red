# Evidence Log — OWASP NodeGoat

Source-to-sink evidence per finding, with line-exact permalinks to commit
[`c5cb68a`](https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8).
Verbatim snippets are in [`code-reference.md`](./code-reference.md). F-001 and
F-002 include local exploitation output; the rest are confirmed against source.

Base permalink: `https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/`

---

## F-003 — SSJS injection via `eval()`

- Sink: [`app/routes/contributions.js` L28-L34](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/contributions.js#L28-L34) · route [`index.js` L52](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L52)

```js
/*jslint evil: true */
// Insecure use of eval() to parse inputs
const preTax   = eval(req.body.preTax);
const afterTax = eval(req.body.afterTax);
const roth     = eval(req.body.roth);
```

- Source: three POST body fields go straight into `eval()`. Validation (`isNaN`, `< 0`) at L47 runs **after** `eval`, so the payload executes before it is checked.
- `/*jslint evil: true */` suppresses the linter's `eval` warning → the risk was seen and overridden.
- DoS proof (floor): `while(true){}`. RCE ceiling (not exploited here): `require('child_process').execSync('id')`, `require('fs').readFileSync('/etc/passwd')`.

## F-004 — Stored XSS (autoescape disabled, admin-facing sink)

- Root cause: [`server.js` L134-L142](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L134-L142)

```js
swig.setDefaults({
    autoescape: false        // Fix for A3-XSS: autoescape: true (commented out)
});
```

- Source: [`profile.js` L42-L50](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/profile.js#L42-L50) reads `req.body.firstName`; [`profile-dao.js` L46-L47](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/data/profile-dao.js#L46-L47) stores it unmodified.
- Sinks (rendered raw in HTML body context):
  - [`layout.html` L75](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/layout.html#L75) — nav bar, every logged-in page
  - [`benefits.html` L51](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/benefits.html#L51) — `{{user.firstName}}`, **admin page** listing every user
  - [`allocations.html` L35](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/allocations.html#L35)
- Chain: payload in a regular user's `firstName` → stored → rendered unencoded in the admin's benefits view → executes in the admin session. `HttpOnly` blocks cookie theft, so the impact is acting *inside* the session, not stealing it.
- Example payload (body context): `<img src=x onerror=fetch('/benefits',{method:'POST',...})>`

## F-002 — NoSQL injection via `$where` *(exploited locally)*

- Sink: [`app/data/allocations-dao.js` L57-L86](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/data/allocations-dao.js#L57-L86)

```js
const parsedUserId = parseInt(userId);
return {
    $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
};
```

- Source: `req.query.threshold` from [`allocations.js` L19-L21](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/allocations.js#L19) — interpolated raw. `userId` is `parseInt()`-guarded; only `threshold` is injectable.
- Local exploitation:

```text
# Full read — breaks out of the stocks comparison, forces the predicate true
GET /allocations/1?threshold=1'; return 1 == '1
  -> returns allocation records for EVERY user (confidentiality breach)

# DoS — hangs the $where JS evaluation on the Mongo server
GET /allocations/1?threshold=0';while(true){}'
  -> MongoDB server unresponsive (availability)
```

- Payloads also documented in the source comment at L67-L68.
- Environment note: `$where` does not trigger on MongoDB Atlas M0; confirmed on a local self-hosted MongoDB.

## F-007 — Missing function-level access control (`/benefits`)

- Routes: [`index.js` L55-L59](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L55-L59)

```js
app.get("/benefits",  isLoggedIn, benefitsHandler.displayBenefits);
app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
/* Fix for A7 — isAdmin check (commented out):
 app.get("/benefits",  isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
 app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits); */
```

- `isAdmin` is absent; `isLoggedIn` only checks authentication.
- The form takes the target `userId` from a hidden field ([`benefits.html` L56](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/benefits.html#L56)), so any logged-in user can set any user's benefits start date.

## F-001 — IDOR on `/allocations/:userId` *(exploited locally)*

- Handler: [`app/routes/allocations.js` L11-L23](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/allocations.js#L11-L23) · route [`index.js` L63](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L63)

```js
/* Fix for A4 Insecure DOR — take user id from session instead of from URL param
   const { userId } = req.session;  */
const { userId } = req.params;      // <-- taken from the URL instead
allocationsDAO.getByUserIdAndThreshold(userId, threshold, ...);
```

- Source `req.params.userId` flows to the lookup with no comparison against `req.session.userId`.
- Local exploitation: authenticated as user A, requesting `/allocations/<B's id>` returned user B's allocations. The commented-out fix confirms the correct remediation was known.

## F-006 — CSRF (protection commented out)

- Middleware: [`server.js` L7](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L7) and [L104-L113](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L104-L113)

```js
// const csrf = require('csurf');          <-- require commented out
/* app.use(csrf());
   app.use((req,res,next) => { res.locals.csrftoken = req.csrfToken(); next(); }); */
```

- Forms still emit the field ([`profile.html` L73](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/profile.html#L73), [`contributions.html` L91](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/contributions.html#L91)):

```html
<input type="hidden" name="_csrf" value="{{csrftoken}}" />
```

- `csrftoken` is never generated → renders empty → never validated. State-changing routes `/profile`, `/contributions`, `/benefits` ([`index.js` L48,L52,L56](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L48)) accept forged cross-site POSTs.
- PoC shape: attacker page auto-submits a `POST /profile` changing the victim's bank account + routing number; browser attaches `connect.sid` automatically.

## F-005 — Session and cookie misconfiguration

- Session: [`server.js` L77-L102](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L77-L102) — only `secret`, `saveUninitialized`, `resave`; no `cookie` block.
- Hardcoded secret: [`config/env/all.js` L8](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/config/env/all.js#L8) → `cookieSecret: "session_cookie_secret_key_here"`, no env override.
- Plain HTTP: [`server.js` L144-L147](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L144-L147) → `http.createServer(app)`.
- Verified against library defaults: express-session sets `httpOnly = true` by default (`session/cookie.js`), so `httpOnly` is **not** a finding here — the commented-out block only makes it explicit. `secure` defaults to `false`; on HTTP the cookie is cleartext. `sameSite` unset. Cookie name defaults to `connect.sid`.
