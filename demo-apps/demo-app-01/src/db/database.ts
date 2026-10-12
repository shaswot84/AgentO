import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In-memory or file-backed database (default: demo.sqlite in root of demo-app)
const dbPath = process.env.DB_PATH || path.resolve(__dirname, '../../demo.sqlite');
export const db = new Database(dbPath);

// Enable foreign keys
db.pragma('foreign_keys = ON');

export function initDatabase() {
  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      email TEXT NOT NULL,
      full_name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      price REAL NOT NULL,
      in_stock INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_name TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      total_price REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'completed',
      shipping_address TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  // Seed default users if table is empty
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
  if (userCount.count === 0) {
    const insertUser = db.prepare(`
      INSERT INTO users (id, username, password, role, email, full_name)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    // Required test users: Alice, Bob, Admin
    insertUser.run(1, 'alice', 'alice123', 'customer', 'alice@agento.local', 'Alice Smith');
    insertUser.run(2, 'bob', 'bob123', 'customer', 'bob@agento.local', 'Bob Jones');
    insertUser.run(3, 'admin', 'admin123', 'admin', 'admin@agento.local', 'System Administrator');
  }

  // Seed default products if table is empty
  const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get() as { count: number };
  if (productCount.count === 0) {
    const insertProduct = db.prepare(`
      INSERT INTO products (name, description, category, price, in_stock)
      VALUES (?, ?, ?, ?, ?)
    `);

    insertProduct.run('SecureKey YubiStick', 'Hardware security key with FIDO2 and U2F support', 'Security', 49.99, 1);
    insertProduct.run('AgentO Threat Radar', 'Real-time DAST and SAST vulnerability scanner license', 'Software', 299.00, 1);
    insertProduct.run('Privacy Guard Webcam Cover', 'Sliding matte black webcam privacy cover', 'Hardware', 9.50, 1);
    insertProduct.run('Encrypted USB Drive 64GB', 'Hardware encrypted storage with keypad', 'Hardware', 79.00, 1);
    insertProduct.run('CyberSec Hoodie', 'High quality dark hoodie for security engineers', 'Apparel', 55.00, 1);
  }

  // Seed default orders if table is empty
  const orderCount = db.prepare('SELECT COUNT(*) as count FROM orders').get() as { count: number };
  if (orderCount.count === 0) {
    const insertOrder = db.prepare(`
      INSERT INTO orders (id, user_id, product_name, quantity, total_price, status, shipping_address)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    // Order 101: Alice's confidential order
    insertOrder.run(101, 1, 'SecureKey YubiStick', 2, 99.98, 'Shipped', '124 Alice Way, Wonderland Apt 4B');
    // Order 102: Alice's second order
    insertOrder.run(102, 1, 'CyberSec Hoodie', 1, 55.00, 'Processing', '124 Alice Way, Wonderland Apt 4B');
    // Order 201: Bob's confidential order
    insertOrder.run(201, 2, 'Encrypted USB Drive 64GB', 1, 79.00, 'Delivered', '742 Evergreen Terrace, Springfield');
    // Order 301: Admin's internal order
    insertOrder.run(301, 3, 'AgentO Threat Radar', 5, 1495.00, 'Completed', 'AgentO HQ, Server Room 1');
  }
}
