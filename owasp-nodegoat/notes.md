# Review Notes — methodology refinements & corrections

Points where an initial conclusion was corrected or sharpened against the
source. Kept because the reasoning is the transferable skill, not the bug.

## Methodology refinements

- **IDOR remediation (F-001).** First instinct: switch IDs to UUIDs. Refined: UUIDs only reduce guessability; they do not add the missing ownership check, which is the root cause. The auth transport (session vs. JWT) is also irrelevant — the check either exists in the handler or it does not.
- **Impact-rating discipline (F-003).** First rating for the `eval()` bug was DoS, based on the easiest payload. Refined to the true ceiling — remote code execution — after reasoning through what attacker-controlled JS in the Node process allows (filesystem, `child_process`, env exfiltration).
- **Payload-to-context matching (F-004).** First proposed a `<script>` payload for an attribute-context sink where it would not fire. Refined: the payload and the defense must both match the specific render context, not the vulnerability class in general — an attribute breakout, or a `javascript:` scheme that survives HTML encoding entirely.
- **One checklist per class (F-006).** Asked how to verify CSRF protection was real, first reached for the session/cookie checklist (flags, secret). Refined: CSRF is its own checklist — route-level middleware **plus** token validation. A `_csrf` field in the form proves nothing on its own.
- **Verify against source, not summaries.** Re-checking every finding against the repo overturned three first-pass conclusions (see below). Lesson: a missing option in config is not a missing protection until the library default is checked.

## Corrections made from the first pass

| Finding | First pass said | Source actually shows |
|---|---|---|
| F-005 session | `httpOnly` missing → XSS can steal the cookie | express-session defaults `httpOnly: true`; cookie is protected. Not a finding. |
| F-004 XSS | `firstNameSafeString` in `href` is HTML-encoded but URL-unsafe | That var is raw and set only on an error path; real root cause is global `autoescape: false`; the wrong-context encode bug is on `doc.website` |
| F-006 CSRF | `csurf` present — check per-route coverage | `csurf` is commented out entirely; forms carry an empty `_csrf` field |
| F-005 secret | Hardcoded secret → forge any session, zero interaction | Signs the cookie only; a session ID must still exist in the server-side store |
