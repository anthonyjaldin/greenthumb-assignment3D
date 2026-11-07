# Changelog

## v1.1 (November 2026): hardening after the assignment

### Security

* **Passwords are hashed with scrypt.** The assignment stored passwords in
  plaintext so the UNION exercise had something to reveal. They now use
  Node's built in scrypt with a random salt per user, are compared in constant
  time, and unknown usernames are checked against a dummy hash so login timing
  does not reveal which accounts exist.
* **Every database value is encoded on output.** Listing titles, species,
  locations, descriptions, timestamps, and usernames were still printed raw.
  Not exploitable with seed data, but each one would become stored XSS once
  users could create content.
* **Database errors are no longer shown to visitors.** The search page printed
  the raw SQL error, which reveals table names and query structure. It is now
  logged on the server and the visitor sees a generic message.
* **Comments are validated.** Comments could be posted to listings that do not
  exist, could be empty, and had no size limit (a 50 KB comment was accepted
  into an in-memory database). Unknown listings now return 404, and empty or
  oversized comments return 400.
* **Sessions expire after 8 hours.** Tokens previously stayed valid until the
  server restarted. Expired sessions are rejected and cleaned up, and the
  cookie carries a matching Max-Age.
* **Additional security headers.** `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, a `form-action`
  CSP directive, and `X-Powered-By` disabled. The logout cookie is cleared with
  the same attributes it was set with.

### Testing

* `npm test` starts the server, runs the exploit suite and new hardening
  checks, and stops the server.
* GitHub Actions runs `npm test` on Node 20 and 22 for every push.
* Exploit 2 now detects a leak of password hashes and usernames, not only
  plaintext passwords. Without this change it would have reported SECURE
  against vulnerable code once passwords were hashed. Verified against a copy
  of the server with the injection reintroduced.

### Documentation

* New README describing the project, setup, testing, and limitations. The
  original assignment brief moved to `docs/ASSIGNMENT.md`.
* Comments in `server.js` and `public/app.js` describe the defenses in place
  instead of the original "fix idea" hints.
* Removed instructor packaging notes that were not part of the project.

## v1.0 (July 2026): assignment submission

* Fixed all five defects: SQL injection in login (FIX 1) and search (FIX 2),
  reflected XSS (FIX 3), stored and DOM based XSS (FIX 4), and cookie flags
  plus a Content Security Policy (FIX 5).
* Wrote the four exploit payloads that prove each vulnerability.
* Wrote `WRITEUP.md` explaining each attack, fix, and its limits.
