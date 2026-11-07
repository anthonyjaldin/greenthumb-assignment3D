// tests/hardening-checks.mjs
// Regression checks for the hardening added after the assignment
// (see CHANGELOG.md). Run through `npm test`, or directly against a running
// server:  TARGET=http://localhost:3000 node tests/hardening-checks.mjs
import { BASE, postForm, getText } from '../exploits/_lib.mjs';

let failures = 0;
function check(ok, name) {
  console.log(`  ${ok ? '\x1b[32m[PASS]\x1b[0m' : '\x1b[31m[FAIL]\x1b[0m'} ${name}`);
  if (!ok) failures++;
}

console.log(`\n=== Hardening checks ===\nTarget: ${BASE}`);

// Security headers
const home = await getText('/');
check(home.headers.get('x-content-type-options') === 'nosniff', 'X-Content-Type-Options: nosniff');
check(home.headers.get('referrer-policy') === 'no-referrer', 'Referrer-Policy: no-referrer');
check(home.headers.get('x-frame-options') === 'DENY', 'X-Frame-Options: DENY');
check(!home.headers.get('x-powered-by'), 'X-Powered-By header is not sent');

// Login with the real password works, wrong password does not
const good = await postForm('/login', { username: 'curator', password: 'GreenThumb!Root#2024' });
const cookie = good.headers.get('set-cookie') || '';
check(/^sid=[a-f0-9]{32};/.test(cookie), 'valid credentials create a session');
check(/max-age=\d+/i.test(cookie), 'session cookie has a Max-Age (sessions expire)');
const bad = await postForm('/login', { username: 'curator', password: 'wrong' });
check(!bad.headers.get('set-cookie'), 'wrong password is rejected');

// The session is honored and logout clears it with matching attributes
const sid = cookie.split(';')[0];
const me = await getText('/me', { cookie: sid });
check(me.status === 200 && me.body.includes('Hello, curator'), 'session cookie grants access to /me');
const logout = await getText('/logout', { cookie: sid });
check(/httponly/i.test(logout.headers.get('set-cookie') || ''), 'logout cookie keeps HttpOnly');
const after = await getText('/me', { cookie: sid });
check(after.status === 302, 'session is invalid after logout');

// Comment validation
const orphan = await postForm('/listing/999/comments', { body: 'hello' });
check(orphan.status === 404, 'comment on a listing that does not exist is rejected (404)');
const empty = await postForm('/listing/2/comments', { body: '   ' });
check(empty.status === 400, 'empty comment is rejected (400)');
const huge = await postForm('/listing/2/comments', { body: 'A'.repeat(5000) });
check(huge.status === 400, 'comment over 1000 characters is rejected (400)');
const ok = await postForm('/listing/2/comments', { body: 'Lovely pup!' });
check(ok.status === 302, 'normal comment is accepted');

// Database output is encoded everywhere, not just in comments
const listing = await getText('/listing/1');
check(!/<script/i.test(listing.body.replace('<script src="/app.js"></script>', '')),
  'listing page contains no inline scripts');

console.log(failures ? `\n\x1b[31m${failures} check(s) failed.\x1b[0m` : '\n\x1b[32mAll hardening checks passed.\x1b[0m');
process.exit(failures ? 1 : 0);
