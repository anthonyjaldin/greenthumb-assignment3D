// server.js  —  GreenThumb (secured build)
// CYSE 411 · Assignment 3
//
// This app started as a deliberately vulnerable starter. The five defects
// (FIX 1 .. FIX 5) are closed; each comment below describes the defense now
// in place. WRITEUP.md explains the attack and the fix for each one.

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { initDb, all, get, run } = require('./lib/db');
const { verifyPassword, DUMMY_HASH } = require('./lib/passwords');

const app = express();

// Do not advertise the framework (Express adds X-Powered-By by default).
app.disable('x-powered-by');
const PORT = process.env.PORT || 3000;

// FIX 5 (part B): restrictive Content-Security-Policy on every response.
// All JS lives in /app.js and all CSS in /styles.css, so no 'unsafe-inline'
// is needed, and injected inline scripts or event handlers will not run.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; " +
      "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; " +
      "form-action 'self'"
  );
  // Browsers must not guess content types (stops a text upload being run
  // as a script), search terms in URLs are not leaked to other sites
  // through the Referer header, and old browsers that ignore
  // frame-ancestors still refuse to frame the site (clickjacking).
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// HTML-encode untrusted text before it is placed in an HTML element or a
// quoted attribute. Not sufficient for URLs, <script> blocks, or CSS.
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}


// ---------------------------------------------------------------------------
// Tiny in-memory session store:  token -> username
// ---------------------------------------------------------------------------
const sessions = new Map();

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach((pair) => {
    const i = pair.indexOf('=');
    if (i > -1) out[pair.slice(0, i).trim()] = decodeURIComponent(pair.slice(i + 1).trim());
  });
  return out;
}

function currentUser(req) {
  const sid = parseCookies(req).sid;
  return sid && sessions.has(sid) ? sessions.get(sid) : null;
}

// ---------------------------------------------------------------------------
// HTML layout helper. All pages share this shell.
// ---------------------------------------------------------------------------
function layout(title, body, req) {
  const user = currentUser(req);
  const nav = user
    ? `<a href="/me">${escapeHtml(user)}</a> · <a href="/logout">log out</a>`
    : `<a href="/login">log in</a>`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} · GreenThumb</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">🌱 GreenThumb</a>
    <form class="search" action="/search" method="get">
      <input name="q" placeholder="Search listings…" aria-label="Search listings">
    </form>
    <nav>${nav}</nav>
  </header>
  <main>${body}</main>
  <footer>GreenThumb · a CYSE 411 teaching app · not for production use</footer>
  <script src="/app.js"></script>
</body>
</html>`;
}

// ===========================================================================
// Home
// ===========================================================================
app.get('/', (req, res) => {
  const listings = all(
    `SELECT id, title, species, location FROM listings ORDER BY created_at DESC`
  );
  const cards = listings
    .map(
      (l) => `<article class="card">
        <h2><a href="/listing/${Number(l.id)}">${escapeHtml(l.title)}</a></h2>
        <p class="species">${escapeHtml(l.species)}</p>
        <p class="meta">📍 ${escapeHtml(l.location)}</p>
      </article>`
    )
    .join('');
  res.send(layout('Home', `<h1>Recent swaps</h1><div class="grid">${cards}</div>`, req));
});

// ===========================================================================
// Search
// ===========================================================================
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  const sort = req.query.sort || 'created_at DESC';

  // ---- FIX 2: SQL injection (data extraction) ---------------------------
  // The search term is bound with "?" placeholders so it is always data.
  // ORDER BY cannot take a bound parameter (it is an identifier, not a
  // value), so the sort option is looked up in a fixed allow-list and
  // anything else falls back to the default.
  const SORT_ALLOW = {
    'created_at DESC': 'created_at DESC',
    'created_at': 'created_at ASC',
    'title': 'title ASC',
    'title DESC': 'title DESC',
    'species': 'species ASC',
    'species DESC': 'species DESC',
    'location': 'location ASC',
  };
  const orderBy = SORT_ALLOW[sort] || 'created_at DESC';
  const like = `%${q}%`;

  const sql =
    `SELECT id, title, species, location FROM listings ` +
    `WHERE title LIKE ? OR species LIKE ? ` +
    `ORDER BY ${orderBy}`;

  let rows = [];
  let error = false;
  try {
    rows = all(sql, [like, like]);
  } catch (e) {
    // Log the details server side; never show raw database errors to the
    // visitor, since they reveal table names and query structure.
    console.error('search query failed:', e.message);
    error = true;
  }

  const results = rows
    .map(
      (r) => `<article class="card">
        <h2><a href="/listing/${Number(r.id)}">${escapeHtml(r.title)}</a></h2>
        <p class="species">${escapeHtml(r.species)}</p>
        <p class="meta">📍 ${escapeHtml(r.location)}</p>
      </article>`
    )
    .join('');

  // ---- FIX 3: reflected XSS ---------------------------------------------
  // The search term is HTML-encoded before it is echoed back.
  const heading = `<h1>Search</h1><p class="note">Showing results for “${escapeHtml(q)}”</p>`;
  const bodyErr = error ? '<p class="error">Search is unavailable right now.</p>' : '';
  const list = rows.length ? `<div class="grid">${results}</div>` : '<p>No matches.</p>';
  res.send(layout('Search', heading + bodyErr + list, req));
});

// ===========================================================================
// Login / logout
// ===========================================================================
app.get('/login', (req, res) => {
  const failed = req.query.failed ? '<p class="error">Invalid credentials.</p>' : '';
  res.send(
    layout(
      'Log in',
      `<h1>Log in</h1>${failed}
       <form class="stack" action="/login" method="post">
         <label>Username <input name="username" autocomplete="username"></label>
         <label>Password <input name="password" type="password" autocomplete="current-password"></label>
         <button type="submit">Log in</button>
       </form>`,
      req
    )
  );
});

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  // ---- FIX 1: SQL injection (authentication bypass) ---------------------
  // Parameterized query: a username like  curator' --  is compared as a
  // literal string instead of rewriting the WHERE clause.
  //
  // Passwords are stored as scrypt hashes, so the row is looked up by
  // username and the password is checked in code. When the username does
  // not exist we still hash against a dummy value, so the response time
  // does not reveal which usernames are real.
  let row = null;
  try {
    row = get(`SELECT id, username, password_hash FROM users WHERE username = ?`, [username]);
  } catch (e) {
    // fall through to failure
  }
  const passwordOk = verifyPassword(password, row ? row.password_hash : DUMMY_HASH);
  const user = row && passwordOk ? row : null;
  if (!user) return res.redirect('/login?failed=1');

  const token = crypto.randomBytes(16).toString('hex');
  sessions.set(token, user.username);

  // ---- FIX 5 (part A): session cookie hardening --------------------------
  // HttpOnly: page scripts (and so XSS payloads) cannot read the cookie.
  // SameSite=Strict: not sent on cross-site requests (CSRF protection).
  // Secure: only sent over HTTPS when the app is served over HTTPS.
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const cookie =
    `sid=${token}; Path=/; HttpOnly; SameSite=Strict` + (secure ? '; Secure' : '');
  res.setHeader('Set-Cookie', cookie);
  res.redirect('/me');
});

app.get('/logout', (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sid);
  // Clear the cookie with the same attributes it was set with.
  res.setHeader('Set-Cookie', 'sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict');
  res.redirect('/');
});

// ===========================================================================
// Profile (requires a session — proves what a stolen cookie is worth)
// ===========================================================================
app.get('/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  const mine = all(
    `SELECT id, title, species FROM listings WHERE user_id = (SELECT id FROM users WHERE username = ?) ORDER BY created_at DESC`,
    [user]
  );
  const list = mine.length
    ? mine
        .map((l) => `<li><a href="/listing/${Number(l.id)}">${escapeHtml(l.title)}</a> — ${escapeHtml(l.species)}</li>`)
        .join('')
    : '<li>You have no listings yet.</li>';
  res.send(
    layout('Profile', `<h1>Hello, ${escapeHtml(user)}</h1><p>Your listings:</p><ul>${list}</ul>`, req)
  );
});

// ===========================================================================
// Listing detail (comments are rendered server-side)
// ===========================================================================
app.get('/listing/:id', (req, res) => {
  const l = get(`SELECT * FROM listings WHERE id = ?`, [Number(req.params.id)]);
  if (!l) return res.status(404).send(layout('Not found', '<h1>Listing not found</h1>', req));

  const comments = all(
    `SELECT author, body, created_at FROM comments WHERE listing_id = ? ORDER BY created_at ASC`,
    [l.id]
  );

  // ---- FIX 4: stored XSS ------------------------------------------------
  // Comment bodies and authors are HTML-encoded on output, so markup saved
  // in a comment is displayed as text for every visitor.
  const commentsHtml = comments.length
    ? comments
        .map(
          (c) => `<div class="comment">
             <p class="comment-body">${escapeHtml(c.body)}</p>
             <p class="comment-meta">— ${escapeHtml(c.author)}, ${escapeHtml(c.created_at)}</p>
           </div>`
        )
        .join('')
    : '<p>No comments yet. Be the first!</p>';

  // Every database value is encoded, even ones that only come from seed data
  // today: once users can create listings, any raw field becomes stored XSS.
  const body = `
    <a class="back" href="/">← all swaps</a>
    <h1>${escapeHtml(l.title)}</h1>
    <p class="species">${escapeHtml(l.species)}</p>
    <p class="meta">📍 ${escapeHtml(l.location)} · posted ${escapeHtml(l.created_at)}</p>
    <p class="desc">${escapeHtml(l.description)}</p>

    <div id="share-banner" data-listing="${Number(l.id)}"></div>

    <section class="comments">
      <h2>Comments</h2>
      <div id="comments">${commentsHtml}</div>
      <form class="stack" action="/listing/${Number(l.id)}/comments" method="post">
        <label>Add a comment
          <textarea name="body" rows="3" maxlength="${MAX_COMMENT_LENGTH}" required placeholder="Say something nice…"></textarea>
        </label>
        <button type="submit">Post comment</button>
      </form>
    </section>`;
  res.send(layout(l.title, body, req));
});

// Post a comment. The body is stored as typed and encoded on output (FIX 4).
const MAX_COMMENT_LENGTH = 1000;

app.post('/listing/:id/comments', (req, res) => {
  const id = Number(req.params.id);
  // Only accept comments for listings that exist; otherwise anyone can fill
  // the comments table with rows attached to ids that will never be shown.
  if (!Number.isInteger(id) || !get(`SELECT id FROM listings WHERE id = ?`, [id])) {
    return res.status(404).send(layout('Not found', '<h1>Listing not found</h1>', req));
  }
  const author = currentUser(req) || 'guest';
  const body = String(req.body.body || '').trim();
  if (!body || body.length > MAX_COMMENT_LENGTH) {
    return res
      .status(400)
      .send(
        layout(
          'Invalid comment',
          `<h1>Comment not posted</h1>
           <p class="error">Comments must be between 1 and ${MAX_COMMENT_LENGTH} characters.</p>
           <a class="back" href="/listing/${id}">← back to the listing</a>`,
          req
        )
      );
  }
  run(`INSERT INTO comments (listing_id, author, body, created_at) VALUES (?, ?, ?, ?)`, [
    id,
    author,
    body,
    new Date().toISOString().slice(0, 16).replace('T', ' '),
  ]);
  res.redirect(`/listing/${id}`);
});

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`GreenThumb → http://localhost:${PORT}`);
  });
});
