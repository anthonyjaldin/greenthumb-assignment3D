# GreenThumb: Break It, Then Fix It

![security tests](https://github.com/anthonyjaldin/greenthumb-assignment3D/actions/workflows/security-tests.yml/badge.svg)

GreenThumb is a small web app where neighbors swap houseplant cuttings. You can
browse listings, search them, log in, and leave comments. It started as a
deliberately vulnerable app in CYSE 411 (Secure Software Engineering) at George
Mason University. My job was to attack it, prove each vulnerability with a
working exploit, then fix the code so the same exploit fails without breaking
any feature.

After the course ended I kept going: I hashed the passwords the assignment had
left in plaintext, reviewed the rest of the app for issues the assignment did
not cover, and added an automated test run so the fixes cannot quietly regress.

## What I found and fixed

| # | Vulnerability | Proof of concept | Fix |
|---|---|---|---|
| 1 | SQL injection, authentication bypass | Username `curator' --` logs in with no password | Parameterized query |
| 2 | SQL injection, data extraction | `UNION SELECT` in the search box dumps the users table | Bound parameters, plus an allow list for the ORDER BY column (identifiers cannot be bound) |
| 3 | Reflected XSS | `<img src=x onerror=...>` in the search term runs script | HTML encoding on output |
| 4 | Stored XSS and DOM based XSS | A comment containing markup runs for every visitor; `#note=<img ...>` in the URL runs through `innerHTML` | Encoding on output; `textContent` instead of `innerHTML` |
| 5 | Session theft and missing browser defenses | Session cookie readable from JavaScript, no CSP | `HttpOnly`, `SameSite=Strict`, and `Secure` cookie flags, plus a strict Content Security Policy |

[WRITEUP.md](WRITEUP.md) walks through each one: the vulnerable code, the exact
payload, why the fix works, and what it does not protect against.

### Beyond the assignment

* **Password hashing.** Passwords were stored in plaintext on purpose for the
  assignment. They are now hashed with scrypt and a random salt per user,
  compared in constant time, and unknown usernames take the same time to reject
  as wrong passwords.
* **Encoding every output.** The assignment fixes covered the search term and
  comments, but listing titles, descriptions, and usernames were still printed
  raw. They are only seed data today, but each would become stored XSS as soon
  as users could create listings, so they are all encoded now.
* **No database errors shown to visitors.** Raw SQL error messages reveal table
  names and query structure, so they are logged on the server instead.
* **Comment validation.** Comments on listings that do not exist, empty
  comments, and comments over 1000 characters are rejected.
* **Session expiry.** Sessions now expire after 8 hours instead of living until
  the server restarts.
* **More security headers.** `X-Content-Type-Options`, `Referrer-Policy`,
  `X-Frame-Options`, a `form-action` CSP directive, and no `X-Powered-By`.
* **Automated testing.** `npm test` starts the app, runs every exploit and a set
  of hardening checks, and fails if anything regresses. GitHub Actions runs it
  on every push.

See [CHANGELOG.md](CHANGELOG.md) for the reasoning behind each change.

## Running it

### Requirements

* Node.js 18 or newer (check with `node --version`)
* Git

### Install and start

1. Download the project and move into it:

   ```bash
   git clone https://github.com/anthonyjaldin/greenthumb-assignment3D.git
   cd greenthumb-assignment3D
   ```

2. Install the two dependencies (Express and sql.js, a WebAssembly build of
   SQLite, so nothing needs to be compiled):

   ```bash
   npm install
   ```

3. Start the app:

   ```bash
   npm start
   ```

4. Open http://localhost:3000 in your browser. To use a different port, run
   `PORT=4000 npm start`.

The database lives in memory and is rebuilt every time the server starts, so a
restart always gives you a clean copy.

### Demo accounts

| Username | Password |
|---|---|
| `curator` | `GreenThumb!Root#2024` |
| `fern_hollow` | `sporeprint77` |
| `cactus_carla` | `prickly-pear-2019` |
| `mossy_mo` | `terrarium4life` |

These are demo values from the seed data. They are hashed when the database is
built and are never stored in plaintext.

## Testing

### Run everything at once

```bash
npm test
```

This starts the server on a free port, runs the five exploit scripts and the
hardening checks against it, and shuts it down. Every exploit should report
`[SECURE]` and every check should report `[PASS]`.

### Run the exploits by hand

With the app running in one terminal (`npm start`), run this in another:

```bash
npm run exploit
```

To run a single exploit, call it directly, for example
`node exploits/01-sqli-login-bypass.mjs`. To aim the suite at a different
address, set `TARGET`, for example `TARGET=http://localhost:4000 npm run exploit`.

[exploits/README.md](exploits/README.md) explains what each script sends and
how it decides whether the attack worked.

### Proving the exploits still work

A test that always passes proves nothing. To confirm an exploit can still
detect a real vulnerability, temporarily undo the matching fix (for example,
concatenate the search term back into the query in `server.js`), restart the
server, and run the suite again. That exploit should report `[VULNERABLE]`.

## Project layout

```
server.js                  routes, output encoding, cookies, security headers
public/app.js              client script for the shared note banner
lib/db.js                  small wrapper around sql.js
lib/passwords.js           scrypt hashing and verification
db/seed.js                 schema and demo data
exploits/                  one attack script per vulnerability, plus run-all
tests/hardening-checks.mjs checks for the changes made after the assignment
scripts/test.mjs           starts the server and runs everything for npm test
docs/ASSIGNMENT.md         the original assignment brief, kept for context
WRITEUP.md                 the security write-up for each fix
```

## Limitations

This is a teaching app, not a production service. Sessions are stored in
memory, there is no rate limiting on the login form, there is no way to create
accounts or listings, and comment posting relies on `SameSite=Strict` cookies
rather than a dedicated CSRF token.
