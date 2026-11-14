// Database connection: real Postgres when DATABASE_URL is set, in-memory pg-mem for local dev.
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id TEXT PRIMARY KEY,
     login TEXT UNIQUE NOT NULL,
     name TEXT NOT NULL DEFAULT '',
     pass TEXT NOT NULL,
     role TEXT NOT NULL DEFAULT 'pending',
     seller TEXT,
     created_at BIGINT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS sessions (
     token TEXT PRIMARY KEY,
     user_id TEXT NOT NULL,
     created_at BIGINT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS clients (
     id TEXT PRIMARY KEY,
     code TEXT UNIQUE NOT NULL,
     seller TEXT NOT NULL DEFAULT '',
     data TEXT NOT NULL,
     version INTEGER NOT NULL DEFAULT 1,
     updated_at BIGINT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS settings (
     key TEXT PRIMARY KEY,
     value TEXT NOT NULL
   )`
];

async function connect() {
  let pool, memory = false;
  const url = process.env.DATABASE_URL;
  if (url) {
    const { Pool } = require("pg");
    const local = /localhost|127\.0\.0\.1|\.railway\.internal/.test(url);
    const ssl = process.env.PGSSL === "0" || local ? false : { rejectUnauthorized: false };
    pool = new Pool({ connectionString: url, ssl, max: 10 });
  } else {
    if (process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_ENVIRONMENT_NAME) {
      throw new Error("DATABASE_URL topilmadi. Railway'da Postgres qo'shing va DATABASE_URL o'zgaruvchisini ulang.");
    }
    const { newDb } = require("pg-mem");
    const mem = newDb();
    const { Pool } = mem.adapters.createPg();
    pool = new Pool();
    memory = true;
  }
  for (const s of SCHEMA) await pool.query(s);
  return { pool, memory };
}

module.exports = { connect };
