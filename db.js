// db.js — sets up the SQLite database and seeds demo data.
// Uses better-sqlite3 (synchronous). The DB file lives at ./juicebox.db.
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const DB_PATH = path.join(__dirname, 'juicebox.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      email TEXT,
      role TEXT DEFAULT 'customer',
      address TEXT,
      card TEXT,
      balance REAL DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      description TEXT,
      price REAL,
      emoji TEXT,
      stock INTEGER DEFAULT 100,
      category TEXT DEFAULT 'Juice'
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER,
      author TEXT,
      body TEXT,
      rating INTEGER,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      items TEXT,
      total REAL,
      coupon TEXT,
      status TEXT DEFAULT 'paid',
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- "Loot" rows that can only be reached via SQL injection (UNION / blind).
    CREATE TABLE IF NOT EXISTS secrets (
      name TEXT,
      flag TEXT
    );

    -- Scoreboard progress, keyed by an anonymous per-browser "player" cookie.
    CREATE TABLE IF NOT EXISTS solves (
      player TEXT,
      challenge TEXT,
      solved_at TEXT DEFAULT (datetime('now')),
      UNIQUE(player, challenge)
    );
  `);
}

function seedSecrets() {
  const c = db.prepare('SELECT COUNT(*) AS c FROM secrets').get().c;
  if (c > 0) return;
  const ins = db.prepare('INSERT INTO secrets (name, flag) VALUES (?, ?)');
  ins.run('union_loot', 'FLAG{un10n_s3l3ct_l00t}');
  ins.run('blind_loot', 'FLAG{bl1nd_but_n0t_d3af}');
}

function seed() {
  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (userCount > 0) return; // already seeded

  const insertUser = db.prepare(
    'INSERT INTO users (username, password, email, role, address, card, balance) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  // NOTE: passwords stored as bare MD5 hashes — intentionally weak.
  insertUser.run('admin', md5('S3cretAdminPass!'), 'admin@juicebox.local', 'admin', '1 HQ Way', '4111-1111-1111-1111', 100000);
  insertUser.run('alice', md5('password123'), 'alice@example.com', 'customer', '42 Apple St', '4012-8888-8888-1881', 250);
  insertUser.run('bob', md5('hunter2'), 'bob@example.com', 'customer', '7 Orchard Ln', '5500-0000-0000-0004', 80);
  insertUser.run('carol', md5('letmein'), 'carol@example.com', 'customer', '9 Citrus Ct', '6011-0009-9013-9424', 1200);

  const insertProduct = db.prepare(
    'INSERT INTO products (name, description, price, emoji, stock, category) VALUES (?, ?, ?, ?, ?, ?)'
  );
  insertProduct.run('Apple Juice (1L)', 'Crisp, cold-pressed apple juice. A customer favorite.', 4.99, '🍎', 200, 'Juice');
  insertProduct.run('Carrot Juice (1L)', 'Sweet, earthy, and loaded with vitamin A.', 5.49, '🥕', 150, 'Juice');
  insertProduct.run('OWASP Cola', 'The official soft drink of broken access control.', 2.99, '🥤', 500, 'Soda');
  insertProduct.run('Green Detox Smoothie', 'Kale, spinach, and a hint of regret.', 7.25, '🥬', 80, 'Smoothie');
  insertProduct.run('Orange Juice (1L)', 'Freshly squeezed, no pulp.', 4.50, '🍊', 175, 'Juice');
  insertProduct.run('Mango Lassi', 'Creamy mango yogurt drink.', 3.75, '🥭', 90, 'Smoothie');
  insertProduct.run('Limited Edition Gold Juice', 'Edible 24k gold flakes. Status in a bottle.', 499.00, '🏆', 5, 'Premium');

  const insertReview = db.prepare(
    'INSERT INTO reviews (product_id, author, body, rating) VALUES (?, ?, ?, ?)'
  );
  insertReview.run(1, 'alice', 'Tastes great, would buy again!', 5);
  insertReview.run(1, 'bob', 'A bit too sweet for me.', 3);
  insertReview.run(3, 'carol', 'I drink this while reading the OWASP Top 10.', 5);

  const insertOrder = db.prepare(
    'INSERT INTO orders (user_id, items, total, coupon, status) VALUES (?, ?, ?, ?, ?)'
  );
  insertOrder.run(2, JSON.stringify([{ id: 1, name: 'Apple Juice (1L)', price: 4.99, qty: 2 }]), 9.98, null, 'paid');
  insertOrder.run(2, JSON.stringify([{ id: 3, name: 'OWASP Cola', price: 2.99, qty: 1 }]), 2.99, null, 'paid');
  insertOrder.run(3, JSON.stringify([{ id: 7, name: 'Limited Edition Gold Juice', price: 499.0, qty: 1 }]), 499.0, null, 'paid');
  insertOrder.run(4, JSON.stringify([{ id: 4, name: 'Green Detox Smoothie', price: 7.25, qty: 3 }]), 21.75, null, 'paid');
}

// Reseed wipes the CONTENT tables (so stored-XSS payloads, junk orders, and
// tampered prices/roles are cleared) but intentionally KEEPS scoreboard progress.
function reseed() {
  db.exec('DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS products; DROP TABLE IF EXISTS reviews; DROP TABLE IF EXISTS orders;');
  init();
  seed();
  seedSecrets();
}

init();
seed();
seedSecrets();

// `npm run seed` -> wipe and reseed from scratch.
if (require.main === module && process.argv.includes('--reseed')) {
  reseed();
  console.log('Database reseeded at', DB_PATH);
}

module.exports = { db, md5, reseed };
