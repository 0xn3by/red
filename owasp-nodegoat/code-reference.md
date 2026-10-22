# NodeGoat: Vulnerable Code Reference

All snippets are copied verbatim from OWASP/NodeGoat at commit
[`c5cb68a`](https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8).
Line numbers refer to that commit, and each heading links to the exact lines.

Base permalink used below:
`https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/`

---

## 1. IDOR (Broken Access Control)

**File:** [`app/routes/allocations.js` L11-L23](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/allocations.js#L11-L23)

```js
this.displayAllocations = (req, res, next) => {
    /*
    // Fix for A4 Insecure DOR -  take user id from session instead of from URL param
    const { userId } = req.session;
    */
    const {
        userId
    } = req.params;
    const {
        threshold
    } = req.query;

    allocationsDAO.getByUserIdAndThreshold(userId, threshold, (err, allocations) => {
```

**Route wiring:** [`app/routes/index.js` L63](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L63)

```js
app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
```

**Source to sink:** `req.params.userId` (URL) flows into `getByUserIdAndThreshold()` with no comparison against `req.session.userId`. `isLoggedIn` checks authentication only.

---

## 2. NoSQL Injection (`$where`)

**File:** [`app/data/allocations-dao.js` L57-L86](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/data/allocations-dao.js#L57-L86)

```js
this.getByUserIdAndThreshold = (userId, threshold, callback) => {
    const parsedUserId = parseInt(userId);

    const searchCriteria = () => {

        if (threshold) {
            /* ...commented-out fix omitted... */
            return {
                $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
            };
        }
        return {
            userId: parsedUserId
        };
    };

    allocationsCol.find(searchCriteria()).toArray((err, allocations) => {
```

**Source to sink:** `req.query.threshold` (from `allocations.js` L19-L21) is interpolated raw into a `$where` string at L78, which MongoDB evaluates as JavaScript. Note `userId` is passed through `parseInt()`, so only `threshold` is injectable.

**Payloads documented in the source comment (L67-L68):** `0';while(true){}'` (DoS) and `1'; return 1 == '1` (returns every user's allocations).

---

## 3. Server-Side JS Injection via `eval()`

**File:** [`app/routes/contributions.js` L28-L34](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/contributions.js#L28-L34)

```js
this.handleContributionsUpdate = (req, res, next) => {

    /*jslint evil: true */
    // Insecure use of eval() to parse inputs
    const preTax = eval(req.body.preTax);
    const afterTax = eval(req.body.afterTax);
    const roth = eval(req.body.roth);
```

**Source to sink:** three POST body fields go straight into `eval()`. The validation at L47 (`isNaN`, `< 0`) runs *after* `eval`, so the payload has already executed by the time it is checked.

**Route:** `app.post("/contributions", isLoggedIn, ...)` ([`index.js` L52](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L52))

---

## 4. Stored XSS

### Root cause: template autoescaping disabled globally

**File:** [`server.js` L134-L142](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L134-L142)

```js
// Template system setup
swig.setDefaults({
    // Autoescape disabled
    autoescape: false
    /*
    // Fix for A3 - XSS, enable auto escaping
    autoescape: true // default value
    */
});
```

### Source: profile update stores `firstName` unmodified

**Files:** [`app/routes/profile.js` L42-L50](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/profile.js#L42-L50) and [`app/data/profile-dao.js` L46-L47](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/data/profile-dao.js#L46-L47)

```js
const {
    firstName,
    lastName,
    ...
} = req.body;
```

```js
if (firstName) {
    user.firstName = firstName;
```

### Sinks: rendered raw in HTML body context

[`app/views/layout.html` L75](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/layout.html#L75) (nav bar, every logged-in page):

```html
<a href="#" class="dropdown-toggle" data-toggle="dropdown"><i class="fa fa-user"></i> {{firstName}} {{lastName}} <b class="caret"></b></a>
```

[`app/views/benefits.html` L51](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/benefits.html#L51) (admin-facing benefits table, lists every user):

```html
<td>{{user.firstName}}</td>
```

[`app/views/allocations.html` L35](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/allocations.html#L35):

```html
<strong>Asset Allocations for {{allocation.firstName}} {{allocation.lastName}}</strong>
```

**Source to sink:** `req.body.firstName` is stored in MongoDB, then rendered with `{{ }}` into the HTML body of other users' pages. With `autoescape: false`, nothing encodes it. The `benefits.html` sink is the high-impact one: it is the page an admin views, so the payload executes in an admin session.

### Secondary: wrong-context encoding (as flagged by the source itself)

[`app/routes/profile.js` L24-L31](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/profile.js#L24-L31)

```js
// @TODO @FIXME
// while the developer intentions were correct in encoding the user supplied input so it
// doesn't end up as an XSS attack, the context is incorrect as it is encoding the firstname for HTML
// while this same variable is also used in the context of a URL link element
doc.website = ESAPI.encoder().encodeForHTML(doc.website);
// fix it by replacing the above with another template variable that is used for
// the context of a URL in a link header
// doc.website = ESAPI.encoder().encodeForURL(doc.website)
```

[`app/views/profile.html` L78](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/profile.html#L78):

```html
<a href="{{firstNameSafeString}}">Google search this profile by name</a>
```

Note: in this commit `firstNameSafeString` is only set in the bank-routing error path ([`profile.js` L64](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/profile.js#L64)) and is the raw `firstName`, not encoded. The `href` sink is reflected, not stored, and upstream issue [#239](https://github.com/OWASP/NodeGoat/issues/239) documents that this example is partly broken.

---

## 5. Session and Cookie Configuration

**File:** [`server.js` L77-L102](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L77-L102)

```js
// Enable session management using express middleware
app.use(session({
    // genid: (req) => {
    //    return genuuid() // use UUIDs for session IDs
    //},
    secret: cookieSecret,
    // Both mandatory in Express v4
    saveUninitialized: true,
    resave: true
    /*
    // Fix for A5 - Security MisConfig
    // Use generic cookie name
    key: "sessionId",
    */

    /*
    // Fix for A3 - XSS
    // TODO: Add "maxAge"
    cookie: {
        httpOnly: true
        // Remember to start an HTTPS server to get this working
        // secure: true
    }
    */

}));
```

**Hardcoded secret:** [`config/env/all.js` L8](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/config/env/all.js#L8)

```js
cookieSecret: "session_cookie_secret_key_here",
```

**Plain HTTP server:** [`server.js` L144-L147](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L144-L147)

```js
// Insecure HTTP connection
http.createServer(app).listen(port, () => {
```

**What is actually wrong here:**
- Session secret is a hardcoded, committed string, and no environment variable overrides it.
- No `cookie` options at all: `secure` defaults to `false`, and the app is served over plain `http`, so the session cookie travels in cleartext.
- No `sameSite` setting.
- Default cookie name (`connect.sid`) is kept, which fingerprints Express.
- `httpOnly` is **not** missing in practice. express-session sets `httpOnly = true` by default (`session/cookie.js` L28 in express-session 1.x). The commented-out block only makes it explicit.

---

## 6. CSRF

**File:** [`server.js` L7](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L7) and [L104-L113](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/server.js#L104-L113)

```js
// const csrf = require('csurf');
```

```js
/*
// Fix for A8 - CSRF
// Enable Express csrf protection
app.use(csrf());
// Make csrf token available in templates
app.use((req, res, next) => {
    res.locals.csrftoken = req.csrfToken();
    next();
});
*/
```

**Form side still has the field:** [`app/views/profile.html` L73](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/profile.html#L73) and [`app/views/contributions.html` L91](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/contributions.html#L91)

```html
<input type="hidden" name="_csrf" value="{{csrftoken}}" />
```

**State-changing routes with no CSRF check:** [`app/routes/index.js` L48, L52, L56](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L48)

```js
app.post("/profile", isLoggedIn, profileHandler.handleProfileUpdate);
app.post("/contributions", isLoggedIn, contributionsHandler.handleContributionsUpdate);
app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
```

**What is actually wrong here:** this is the half-present case from the two-part checklist. The forms emit a `_csrf` field, but the server-side middleware is commented out, so the token is never generated (it renders empty) and never validated. A form with a token field is not evidence of CSRF protection.

---

## 7. Missing Function-Level Access Control (bonus, already reviewed)

**File:** [`app/routes/index.js` L55-L59](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/index.js#L55-L59)

```js
app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits);
app.post("/benefits", isLoggedIn, benefitsHandler.updateBenefits);
/* Fix for A7 - checks user role to implement  Function Level Access Control
 app.get("/benefits", isLoggedIn, isAdmin, benefitsHandler.displayBenefits);
 app.post("/benefits", isLoggedIn, isAdmin, benefitsHandler.updateBenefits);
```

**Note:** the benefits form ([`benefits.html` L56](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/views/benefits.html#L56)) also takes the target `userId` from a hidden field, so any logged-in user can update any user's benefits start date.

---

## Also visible in the same files (not yet reviewed)

- **Vulnerable dependency, exact pin:** `"marked": "0.3.5"` in [`package.json` L17](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/package.json#L17). No caret, so it never moves to the patched release.
- **ReDoS:** `const regexPattern = /([0-9]+)+\#/;` in [`profile.js` L59](https://github.com/OWASP/NodeGoat/blob/c5cb68a7084e4ae7dcc60e6a98768720a81841e8/app/routes/profile.js#L59), nested quantifier applied to `req.body.bankRouting`.
