// lib/passwords.js
// Password hashing with scrypt, which is built into Node's crypto module.
//
// scrypt is deliberately slow and memory hard, so an attacker who steals the
// users table has to spend real work on every guess, and the random per user
// salt means identical passwords produce different hashes.
//
// Stored format:  scrypt$<N>$<r>$<p>$<salt hex>$<hash hex>
// Keeping the parameters in the string lets the cost be raised later without
// breaking existing hashes.

const crypto = require('crypto');

const PARAMS = { N: 16384, r: 8, p: 1 };
const KEY_LENGTH = 32;
const SALT_BYTES = 16;

function hashPassword(password) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const hash = crypto.scryptSync(String(password), salt, KEY_LENGTH, PARAMS);
  const { N, r, p } = PARAMS;
  return ['scrypt', N, r, p, salt.toString('hex'), hash.toString('hex')].join('$');
}

function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, N, r, p, saltHex, hashHex] = parts;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(String(password), Buffer.from(saltHex, 'hex'), expected.length, {
    N: Number(N),
    r: Number(r),
    p: Number(p),
  });
  // Constant time comparison so response timing does not reveal how many
  // bytes of the hash matched.
  return crypto.timingSafeEqual(actual, expected);
}

// A hash of a random value, used to spend the same time on logins for
// usernames that do not exist (see the login handler).
const DUMMY_HASH = hashPassword(crypto.randomBytes(16).toString('hex'));

module.exports = { hashPassword, verifyPassword, DUMMY_HASH };
