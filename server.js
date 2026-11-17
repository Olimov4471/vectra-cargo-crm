"use strict";
const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const path = require("path");
const { connect } = require("./db");

// ---- Business constants (must match public/index.html) ----
const SELL = ["Muhammad Ali", "Bobur", "Sirojiddin.P", "Sirojiddin.O"];
const ST = ["Yangi mijoz", "Qayta aloqa", "Kelishildi", "Sotildi", "Sotib olmadi"];
const PL = ["yangi", "qayta", "doimiy"];
const DATA_KEYS = ["n", "tel", "src", "d", "st", "pl", "rc", "q", "note", "why", "wq", "vol", "wt", "cb", "sales", "tasks", "log"];
const PNL_DEFAULTS = {
  buy: 7.5, sell: 10, kpi: 0.5, fixed: 620, smm: 800, target: 800, obet: 300, kuller: 80,
  goal: 2000, plan1: 1500, growth: 0.15, rep: 0, sellers: 4, avgKg: 10, qShare: 0.5, conv: 0.5,
  invShare: 0.7, reinv: 0.7, invMonths: 6, invAfter: 0, start: ""
};

const COOKIE = "sid";
const SESSION_DAYS = 365;
const now = () => Date.now();
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const rid = (n = 12) => crypto.randomBytes(n).toString("hex");

const CODE_PREFIX = "BVA-";
// Client code typed by staff. A bare prefix ("BVA-") or blank means "no code yet".
function normCode(v) {
  const s = (v === undefined || v === null ? "" : String(v)).trim().slice(0, 40);
  return s.toUpperCase() === CODE_PREFIX ? "" : s;
}
function parseCookies(h) {
  const o = {};
  (h || "").split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return o;
}
const str = (v, max = 2000) => (v === undefined || v === null ? "" : String(v)).slice(0, max);

async function main() {
  const { pool, memory } = await connect();
  const q = (sql, params) => pool.query(sql, params).then(r => r.rows);
  const one = async (sql, params) => (await q(sql, params))[0] || null;

  // ---- Bootstrap admin from env ----
  const AL = (process.env.ADMIN_LOGIN || "").trim().toLowerCase();
  const AP = process.env.ADMIN_PASSWORD || "";
  if (AL && AP) {
    const u = await one("SELECT * FROM users WHERE login=$1", [AL]);
    if (!u) {
      await q("INSERT INTO users(id,login,name,pass,role,seller,created_at) VALUES($1,$2,$3,$4,'admin',NULL,$5)",
        [rid(8), AL, process.env.ADMIN_NAME || "Admin", await bcrypt.hash(AP, 10), now()]);
      console.log("Admin yaratildi:", AL);
    } else {
      if (u.role !== "admin") await q("UPDATE users SET role='admin', seller=NULL WHERE id=$1", [u.id]);
      if (process.env.ADMIN_RESET_PASSWORD === "1")
        await q("UPDATE users SET pass=$1 WHERE id=$2", [await bcrypt.hash(AP, 10), u.id]);
    }
  }

  const app = express();
  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(express.json({ limit: "2mb" }));
  app.use((req, res, next) => {
    res.set("X-Content-Type-Options", "nosniff");
    res.set("Referrer-Policy", "same-origin");
    next();
  });

  // ---- Auth helpers ----
  const pubUser = u => ({ id: u.id, login: u.login, name: u.name, role: u.role, seller: u.seller || null });
  const author = u => (u.role === "admin" ? "Admin" : u.seller || u.name || "?");
  const isStaff = u => u && (u.role === "admin" || (u.role === "seller" && u.seller));
  const vis = (u, row) => u.role === "admin" || !row.seller || row.seller === u.seller;

  async function newSession(res, req, userId) {
    const token = rid(32);
    await q("INSERT INTO sessions(token,user_id,created_at) VALUES($1,$2,$3)", [sha(token), userId, now()]);
    const secure = req.secure ? "; Secure" : "";
    res.set("Set-Cookie", `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${secure}`);
  }
  async function loadUser(req) {
    const t = parseCookies(req.headers.cookie)[COOKIE];
    if (!t) return null;
    const s = await one("SELECT * FROM sessions WHERE token=$1", [sha(t)]);
    if (!s) return null;
    if (now() - Number(s.created_at) > SESSION_DAYS * 86400000) {
      await q("DELETE FROM sessions WHERE token=$1", [s.token]);
      return null;
    }
    return one("SELECT * FROM users WHERE id=$1", [s.user_id]);
  }
  const wrap = fn => (req, res) => fn(req, res).catch(e => {
    console.error(e);
    res.status(500).json({ error: "Server xatosi. Qayta urinib ko'ring." });
  });
  const need = (level, fn) => wrap(async (req, res) => {
    const u = await loadUser(req);
    if (!u) return res.status(401).json({ error: "Tizimga kiring." });
    if (level === "staff" && !isStaff(u)) return res.status(403).json({ error: "Administrator tasdig'i kerak." });
    if (level === "admin" && u.role !== "admin") return res.status(403).json({ error: "Faqat administrator uchun." });
    req.user = u;
    return fn(req, res);
  });

  // Simple login rate-limit
  const fails = new Map();
  const limited = key => {
    const f = fails.get(key);
    return f && f.n >= 8 && now() - f.t < 15 * 60000;
  };
  const fail = key => {
    const f = fails.get(key);
    if (!f || now() - f.t > 15 * 60000) fails.set(key, { n: 1, t: now() });
    else f.n++;
  };

  // ---- Realtime (Server-Sent Events) ----
  const conns = new Set();
  const send = (c, m) => { try { c.res.write("data: " + JSON.stringify(m) + "\n\n"); } catch (e) {} };
  function pushClient(row) {
    const doc = toClient(row);
    conns.forEach(c => send(c, vis(c.user, row) ? { type: "upsert", client: doc } : { type: "remove", id: row.id }));
  }
  const pushRemove = id => conns.forEach(c => send(c, { type: "remove", id }));
  const pushAdmins = m => conns.forEach(c => c.user.role === "admin" && send(c, m));
  function kickUser(id) {
    conns.forEach(c => {
      if (c.user.id === id) { send(c, { type: "me" }); try { c.res.end(); } catch (e) {} conns.delete(c); }
    });
  }

  // ---- Client documents ----
  function toClient(row) {
    let d = {};
    try { d = JSON.parse(row.data); } catch (e) {}
    return Object.assign(d, { id: row.id, code: row.code || "", sell: row.seller || "", _v: Number(row.version) });
  }
  function cleanData(body) {
    const d = {};
    DATA_KEYS.forEach(k => { if (body[k] !== undefined) d[k] = body[k]; });
    d.n = str(d.n, 200).trim();
    ["tel", "src", "d", "note", "why", "wq", "vol", "wt", "cb"].forEach(k => { if (d[k] !== undefined) d[k] = str(d[k], 4000); });
    if (!ST.includes(d.st)) d.st = "Yangi mijoz";
    if (!PL.includes(d.pl)) d.pl = "yangi";
    d.rc = Math.max(0, parseInt(d.rc, 10) || 0);
    d.q = !!d.q;
    d.sales = (Array.isArray(d.sales) ? d.sales : []).slice(0, 2000).map(x => ({
      d: str(x && x.d, 10), kg: str(x && x.kg, 30), sum: str(x && x.sum, 30), pl: PL.includes(x && x.pl) ? x.pl : "yangi"
    }));
    d.tasks = (Array.isArray(d.tasks) ? d.tasks : []).slice(0, 2000).map(x => ({
      d: str(x && x.d, 16), tx: str(x && x.tx, 1000), done: !!(x && x.done)
    }));
    d.log = Array.isArray(d.log) ? d.log : [];
    return d;
  }

  // ---- Routes: auth ----
  app.get("/healthz", (req, res) => res.json({ ok: true, memory }));

  app.post("/api/register", wrap(async (req, res) => {
    const name = str(req.body.name, 80).trim();
    const login = str(req.body.login, 60).trim().toLowerCase();
    const pass = str(req.body.password, 200);
    if (name.length < 2) return res.status(400).json({ error: "Ismingizni yozing." });
    if (!/^[a-z0-9._@-]{3,60}$/.test(login)) return res.status(400).json({ error: "Login kamida 3 belgi: lotin harflari, raqam, . _ @ -" });
    if (pass.length < 6) return res.status(400).json({ error: "Parol kamida 6 belgidan iborat bo'lsin." });
    if (await one("SELECT id FROM users WHERE login=$1", [login])) return res.status(409).json({ error: "Bu login band." });
    const admins = await one("SELECT COUNT(*) AS n FROM users WHERE role='admin'");
    const role = Number(admins.n) === 0 && !AL ? "admin" : "pending";
    const id = rid(8);
    await q("INSERT INTO users(id,login,name,pass,role,seller,created_at) VALUES($1,$2,$3,$4,$5,NULL,$6)",
      [id, login, name, await bcrypt.hash(pass, 10), role, now()]);
    await newSession(res, req, id);
    pushAdmins({ type: "staff" });
    res.json(pubUser(await one("SELECT * FROM users WHERE id=$1", [id])));
  }));

  app.post("/api/login", wrap(async (req, res) => {
    const login = str(req.body.login, 60).trim().toLowerCase();
    const pass = str(req.body.password, 200);
    const key = req.ip + "|" + login;
    if (limited(key)) return res.status(429).json({ error: "Juda ko'p urinish. 15 daqiqadan keyin qayta urining." });
    const u = await one("SELECT * FROM users WHERE login=$1", [login]);
    if (!u || !(await bcrypt.compare(pass, u.pass))) {
      fail(key);
      return res.status(401).json({ error: "Login yoki parol noto'g'ri." });
    }
    fails.delete(key);
    await newSession(res, req, u.id);
    res.json(pubUser(u));
  }));

  app.post("/api/logout", wrap(async (req, res) => {
    const t = parseCookies(req.headers.cookie)[COOKIE];
    if (t) await q("DELETE FROM sessions WHERE token=$1", [sha(t)]);
    res.set("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
    res.json({ ok: true });
  }));

  app.get("/api/me", need("any", async (req, res) => res.json(pubUser(req.user))));

  // ---- Routes: clients ----
  app.get("/api/clients", need("staff", async (req, res) => {
    const rows = await q("SELECT * FROM clients");
    res.json(rows.filter(r => vis(req.user, r)).map(toClient));
  }));

  app.get("/api/code-free", need("staff", async (req, res) => {
    const code = normCode(req.query.code);
    const id = str(req.query.id, 64);
    if (!code) return res.json({ free: false });
    const r = await one("SELECT id FROM clients WHERE code=$1 AND id<>$2", [code, id || ""]);
    res.json({ free: !r });
  }));

  app.get("/api/clients/:id", need("staff", async (req, res) => {
    const r = await one("SELECT * FROM clients WHERE id=$1", [req.params.id]);
    if (!r || !vis(req.user, r)) return res.status(404).json({ error: "Mijoz topilmadi." });
    res.json(toClient(r));
  }));

  app.put("/api/clients/:id", need("staff", async (req, res) => {
    const u = req.user, id = str(req.params.id, 64), b = req.body || {};
    if (!/^[A-Za-z0-9_-]{4,64}$/.test(id)) return res.status(400).json({ error: "Noto'g'ri ID." });
    const d = cleanData(b);
    if (!d.n) return res.status(400).json({ error: "Mijoz ismini yozing: ismsiz saqlab bo'lmaydi." });
    const ex = await one("SELECT * FROM clients WHERE id=$1", [id]);
    const adm = u.role === "admin";
    let seller, code, oldLog = [];

    if (ex) {
      if (!vis(u, ex)) return res.status(403).json({ error: "Bu mijoz sizga biriktirilmagan." });
      if (b._v !== undefined && Number(b._v) !== Number(ex.version))
        return res.status(409).json({ error: "Bu mijozni boshqa xodim o'zgartirdi. Ma'lumot yangilandi, qayta kiriting.", client: toClient(ex) });
      try { oldLog = JSON.parse(ex.data).log || []; } catch (e) {}
      seller = adm ? str(b.sell, 80) : ex.seller;
    } else {
      seller = adm ? str(b.sell, 80) : u.seller;
    }
    // Staff type the client code themselves (prefix "BVA-"); it may stay empty.
    code = normCode(b.code);
    if (seller && !SELL.includes(seller)) return res.status(400).json({ error: "Noma'lum mas'ul xodim." });

    if (code) {
      const dup = await one("SELECT id FROM clients WHERE code=$1 AND id<>$2", [code, id]);
      if (dup) return res.status(409).json({ error: "Bunday mijoz kodi band: " + code });
    }

    // History is append-only; new entries get the real author.
    const by = author(u);
    const added = d.log.slice(oldLog.length).slice(0, 200).map(x => ({
      t: Number(x && x.t) || now(), tx: str(x && x.tx, 2000), by
    }));
    d.log = oldLog.concat(added);

    const data = JSON.stringify(d);
    if (ex) {
      await q("UPDATE clients SET code=$1, seller=$2, data=$3, version=version+1, updated_at=$4 WHERE id=$5",
        [code || null, seller || "", data, now(), id]);
    } else {
      await q("INSERT INTO clients(id,code,seller,data,version,updated_at) VALUES($1,$2,$3,$4,1,$5)",
        [id, code || null, seller || "", data, now()]);
    }
    const row = await one("SELECT * FROM clients WHERE id=$1", [id]);
    pushClient(row);
    res.json(toClient(row));
  }));

  app.delete("/api/clients/:id", need("admin", async (req, res) => {
    await q("DELETE FROM clients WHERE id=$1", [req.params.id]);
    pushRemove(req.params.id);
    res.json({ ok: true });
  }));

  // ---- Routes: staff (admin) ----
  app.get("/api/staff", need("admin", async (req, res) => {
    const rows = await q("SELECT * FROM users ORDER BY created_at");
    res.json({
      pending: rows.filter(r => r.role === "pending").map(pubUser),
      staff: rows.filter(r => r.role === "seller").map(pubUser),
      admins: rows.filter(r => r.role === "admin").map(pubUser)
    });
  }));
  const genPass = () => {
    const A = "abcdefghjkmnpqrstuvwxyz23456789";
    let s = "";
    for (let i = 0; i < 10; i++) s += A[crypto.randomInt(A.length)];
    return s;
  };
  app.post("/api/staff/create", need("admin", async (req, res) => {
    const name = str(req.body.name, 80).trim();
    const login = str(req.body.login, 60).trim().toLowerCase();
    const seller = str(req.body.seller, 80);
    let pass = str(req.body.password, 200);
    if (!SELL.includes(seller)) return res.status(400).json({ error: "Xodim kimligini tanlang." });
    if (!/^[a-z0-9._@-]{3,60}$/.test(login)) return res.status(400).json({ error: "Login kamida 3 belgi: lotin harflari, raqam, . _ @ -" });
    if (pass && pass.length < 6) return res.status(400).json({ error: "Parol kamida 6 belgidan iborat bo'lsin (yoki bo'sh qoldiring)." });
    if (await one("SELECT id FROM users WHERE login=$1", [login])) return res.status(409).json({ error: "Bu login band." });
    if (!pass) pass = genPass();
    const id = rid(8);
    await q("INSERT INTO users(id,login,name,pass,role,seller,created_at) VALUES($1,$2,$3,$4,'seller',$5,$6)",
      [id, login, name || seller, await bcrypt.hash(pass, 10), seller, now()]);
    pushAdmins({ type: "staff" });
    res.json({ login, password: pass, seller });
  }));
  app.post("/api/staff/:id/reset-password", need("admin", async (req, res) => {
    const u = await one("SELECT * FROM users WHERE id=$1", [req.params.id]);
    if (!u || u.role === "admin") return res.status(404).json({ error: "Foydalanuvchi topilmadi." });
    let pass = str(req.body && req.body.password, 200);
    if (pass && pass.length < 6) return res.status(400).json({ error: "Parol kamida 6 belgidan iborat bo'lsin (yoki bo'sh qoldiring)." });
    if (!pass) pass = genPass();
    await q("UPDATE users SET pass=$1 WHERE id=$2", [await bcrypt.hash(pass, 10), u.id]);
    await q("DELETE FROM sessions WHERE user_id=$1", [u.id]);
    kickUser(u.id);
    res.json({ login: u.login, password: pass });
  }));
  app.post("/api/staff/:id/approve", need("admin", async (req, res) => {
    const seller = str(req.body.seller, 80);
    if (!SELL.includes(seller)) return res.status(400).json({ error: "Xodim ismini tanlang." });
    const u = await one("SELECT * FROM users WHERE id=$1", [req.params.id]);
    if (!u || u.role === "admin") return res.status(404).json({ error: "Foydalanuvchi topilmadi." });
    await q("UPDATE users SET role='seller', seller=$1 WHERE id=$2", [seller, u.id]);
    kickUser(u.id);
    pushAdmins({ type: "staff" });
    res.json({ ok: true });
  }));
  app.post("/api/staff/:id/reject", need("admin", async (req, res) => {
    const u = await one("SELECT * FROM users WHERE id=$1", [req.params.id]);
    if (!u || u.role === "admin") return res.status(404).json({ error: "Foydalanuvchi topilmadi." });
    await q("DELETE FROM sessions WHERE user_id=$1", [u.id]);
    await q("DELETE FROM users WHERE id=$1", [u.id]);
    kickUser(u.id);
    pushAdmins({ type: "staff" });
    res.json({ ok: true });
  }));
  app.post("/api/staff/:id/revoke", need("admin", async (req, res) => {
    const u = await one("SELECT * FROM users WHERE id=$1", [req.params.id]);
    if (!u || u.role === "admin") return res.status(404).json({ error: "Foydalanuvchi topilmadi." });
    await q("UPDATE users SET role='pending', seller=NULL WHERE id=$1", [u.id]);
    kickUser(u.id);
    pushAdmins({ type: "staff" });
    res.json({ ok: true });
  }));

  // ---- Routes: PNL settings (admin) ----
  async function getPnl() {
    const r = await one("SELECT value FROM settings WHERE key='pnl'");
    let v = {};
    try { v = r ? JSON.parse(r.value) : {}; } catch (e) {}
    return Object.assign({}, PNL_DEFAULTS, v);
  }
  app.get("/api/settings/pnl", need("admin", async (req, res) => res.json(await getPnl())));
  app.put("/api/settings/pnl", need("admin", async (req, res) => {
    const cur = await getPnl(), b = req.body || {};
    Object.keys(PNL_DEFAULTS).forEach(k => {
      if (b[k] === undefined) return;
      if (k === "start") cur.start = /^\d{4}-\d{2}$/.test(b.start) ? b.start : "";
      else { const n = Number(b[k]); if (isFinite(n)) cur[k] = n; }
    });
    const val = JSON.stringify(cur);
    const ex = await one("SELECT key FROM settings WHERE key='pnl'");
    if (ex) await q("UPDATE settings SET value=$1 WHERE key='pnl'", [val]);
    else await q("INSERT INTO settings(key,value) VALUES('pnl',$1)", [val]);
    pushAdmins({ type: "settings", value: cur });
    res.json(cur);
  }));

  // ---- SSE stream ----
  app.get("/api/stream", need("staff", async (req, res) => {
    res.set({ "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
    res.flushHeaders();
    res.write("retry: 3000\n\n");
    const c = { res, user: req.user };
    conns.add(c);
    req.on("close", () => conns.delete(c));
  }));
  setInterval(() => conns.forEach(c => { try { c.res.write(": ping\n\n"); } catch (e) {} }), 25000);

  // ---- Static frontend ----
  app.use(express.static(path.join(__dirname, "public"), { index: "index.html", maxAge: 0 }));
  app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => console.log(`CRM ishga tushdi: http://localhost:${port}` + (memory ? "  (DIQQAT: xotiradagi baza, qayta ishga tushganda ma'lumot o'chadi)" : "")));
}

main().catch(e => { console.error(e.message || e); process.exit(1); });
