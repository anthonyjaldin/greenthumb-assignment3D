// db/seed.js
// Returns the SQL that creates and populates the GreenThumb database.
//
// GreenThumb is a small community board where neighbours list houseplant
// cuttings they want to swap, and leave comments on each other's listings.
//
// PASSWORDS: the original assignment stored these in plaintext so the UNION
// injection exercise had something dramatic to reveal. They are now hashed
// with scrypt (lib/passwords.js) when the database is built. The plaintext
// values below exist only because this is demo seed data that the exploit
// scripts log in with; a real app would never keep passwords in source.

const { hashPassword } = require('../lib/passwords');

// Escape a value for use inside a single quoted SQL literal in the seed.
function sqlString(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

const SEED_USERS = [
  [1, 'fern_hollow', 'sporeprint77', 'Ferns, mosses, and anything that likes shade.'],
  [2, 'cactus_carla', 'prickly-pear-2019', 'Desert succulents only. Trade at my own risk.'],
  [3, 'mossy_mo', 'terrarium4life', 'Building tiny worlds in glass jars.'],
  [4, 'curator', 'GreenThumb!Root#2024', 'Site curator. Do not share this account.'],
];

function buildSeed() {
  return `
    CREATE TABLE users (
      id       INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      bio      TEXT
    );

    CREATE TABLE listings (
      id          INTEGER PRIMARY KEY,
      user_id     INTEGER NOT NULL,
      title       TEXT NOT NULL,
      species     TEXT NOT NULL,
      location    TEXT NOT NULL,
      description TEXT NOT NULL,
      created_at  TEXT NOT NULL
    );

    CREATE TABLE comments (
      id         INTEGER PRIMARY KEY,
      listing_id INTEGER NOT NULL,
      author     TEXT NOT NULL,
      body       TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    INSERT INTO users (id, username, password_hash, bio) VALUES
      ${SEED_USERS.map(
        ([id, username, password, bio]) =>
          `(${id}, ${sqlString(username)}, ${sqlString(hashPassword(password))}, ${sqlString(bio)})`
      ).join(',\n      ')};

    INSERT INTO listings (id, user_id, title, species, location, description, created_at) VALUES
      (1, 1, 'Split-leaf philodendron cutting', 'Monstera deliciosa', 'North Ward',
          'Rooted node with two healthy leaves. Looking to swap for a trailing pothos.', '2026-05-02 09:14'),
      (2, 2, 'Golden barrel cactus pup',        'Echinocactus grusonii','Old Mill',
          'Detached pup, callused and ready to pot. Prefers gritty soil.', '2026-05-03 16:40'),
      (3, 3, 'Java moss portion',               'Taxiphyllum barbieri', 'Riverside',
          'Palm-sized clump. Great for terrariums and shrimp tanks.', '2026-05-05 11:02'),
      (4, 1, 'Maidenhair fern division',        'Adiantum raddianum',   'North Ward',
          'A rooted division from my kitchen plant. Keep it humid.', '2026-05-06 08:20'),
      (5, 2, 'String of pearls strand',         'Curio rowleyanus',     'Old Mill',
          'Long strand, easy to propagate. Bright indirect light.', '2026-05-08 14:55'),
      (6, 3, 'Nerve plant cuttings (x3)',       'Fittonia albivenis',   'Riverside',
          'Three pink-veined cuttings. They faint dramatically when thirsty.', '2026-05-09 19:31');

    INSERT INTO comments (id, listing_id, author, body, created_at) VALUES
      (1, 1, 'mossy_mo',     'Still available? I have a marble queen pothos to trade.', '2026-05-02 10:05'),
      (2, 1, 'cactus_carla', 'Beautiful leaves on that one.',                          '2026-05-02 12:30'),
      (3, 3, 'fern_hollow',  'Java moss is the best. Grabbing some for my terrarium.',  '2026-05-05 13:12');
  `;
}

module.exports = { buildSeed };
