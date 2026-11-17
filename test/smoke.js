// End-to-end API smoke test against an in-memory database.
// Run: npm test
const { spawn } = require("child_process");
const path = require("path");
const assert = require("assert");

const PORT = 3999;
const BASE = "http://localhost:" + PORT;
const env = Object.assign({}, process.env, { PORT: String(PORT), ADMIN_LOGIN: "admin", ADMIN_PASSWORD: "admin123" });
delete env.DATABASE_URL;

function jar() {
  let cookie = "";
  return async (method, url, body) => {
    const r = await fetch(BASE + url, {
      method,
      headers: Object.assign({ cookie }, body ? { "Content-Type": "application/json" } : {}),
      body: body ? JSON.stringify(body) : undefined
    });
    const sc = r.headers.get("set-cookie");
    if (sc) cookie = sc.split(";")[0];
    let j = null;
    try { j = await r.json(); } catch (e) {}
    return { status: r.status, body: j };
  };
}

(async () => {
  const srv = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], { env, stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((res, rej) => {
    srv.stdout.on("data", d => { if (String(d).includes("ishga tushdi")) res(); });
    srv.on("exit", c => rej(new Error("server exited " + c)));
  });
  let ok = 0;
  const t = async (name, fn) => { await fn(); ok++; console.log("  ✓ " + name); };
  try {
    const A = jar(), S = jar(), S2 = jar();
    await t("admin login", async () => {
      const r = await A("POST", "/api/login", { login: "admin", password: "admin123" });
      assert.equal(r.status, 200); assert.equal(r.body.role, "admin");
    });
    await t("wrong password rejected", async () => {
      const r = await jar()("POST", "/api/login", { login: "admin", password: "nope" });
      assert.equal(r.status, 401);
    });
    await t("seller registers -> pending, no data access", async () => {
      const r = await S("POST", "/api/register", { name: "Bobur T", login: "bobur", password: "secret1" });
      assert.equal(r.status, 200); assert.equal(r.body.role, "pending");
      assert.equal((await S("GET", "/api/clients")).status, 403);
    });
    await t("admin approves seller as Bobur", async () => {
      const st = await A("GET", "/api/staff");
      const p = st.body.pending.find(x => x.login === "bobur");
      assert.ok(p);
      assert.equal((await A("POST", `/api/staff/${p.id}/approve`, { seller: "Bobur" })).status, 200);
      const me = await S("GET", "/api/me");
      assert.equal(me.body.role, "seller"); assert.equal(me.body.seller, "Bobur");
    });
    await t("nameless client rejected", async () => {
      const r = await S("PUT", "/api/clients/ctest0001", { n: "  ", log: [] });
      assert.equal(r.status, 400);
    });
    let c1;
    await t("seller creates client -> auto-assigned + code generated", async () => {
      const r = await S("PUT", "/api/clients/ctest0001", { n: "Ali", sell: "Muhammad Ali", code: "HACK", log: [{ t: 1, tx: "Mijoz yaratildi", by: "Admin" }] });
      assert.equal(r.status, 200); c1 = r.body;
      assert.equal(c1.sell, "Bobur");
      assert.match(c1.code, /^M-[A-Z0-9]{5}$/);
      assert.equal(c1.log[0].by, "Bobur");
    });
    await t("seller cannot change seller/code, cannot delete", async () => {
      const r = await S("PUT", "/api/clients/ctest0001", Object.assign({}, c1, { sell: "", code: "X-1" }));
      assert.equal(r.status, 200); assert.equal(r.body.sell, "Bobur"); assert.equal(r.body.code, c1.code);
      c1 = r.body;
      assert.equal((await S("DELETE", "/api/clients/ctest0001")).status, 403);
    });
    await t("stale version -> 409", async () => {
      const r = await S("PUT", "/api/clients/ctest0001", Object.assign({}, c1, { _v: 1 }));
      assert.equal(r.status, 409); assert.ok(r.body.client);
    });
    await t("history is append-only", async () => {
      const r = await S("PUT", "/api/clients/ctest0001", Object.assign({}, c1, { log: [{ t: 2, tx: "tampered" }, { t: 3, tx: "new" }] }));
      assert.equal(r.status, 200);
      assert.equal(r.body.log[0].tx, "Mijoz yaratildi");
      c1 = r.body;
    });
    await t("admin creates client for other seller; Bobur cannot see it", async () => {
      const r = await A("PUT", "/api/clients/ctest0002", { n: "Vali", sell: "Muhammad Ali", code: "M-AAAAA", log: [] });
      assert.equal(r.status, 200); assert.equal(r.body.code, "M-AAAAA");
      const L = (await S("GET", "/api/clients")).body;
      assert.ok(L.find(x => x.id === "ctest0001")); assert.ok(!L.find(x => x.id === "ctest0002"));
      assert.equal((await S("GET", "/api/clients/ctest0002")).status, 404);
      const w = await S("PUT", "/api/clients/ctest0002", { n: "hack", log: [] });
      assert.equal(w.status, 403);
    });
    await t("unassigned client visible to seller", async () => {
      await A("PUT", "/api/clients/ctest0003", { n: "Free", sell: "", log: [] });
      const L = (await S("GET", "/api/clients")).body;
      assert.ok(L.find(x => x.id === "ctest0003"));
    });
    await t("duplicate code rejected", async () => {
      const cur = (await A("GET", "/api/clients/ctest0003")).body;
      const r = await A("PUT", "/api/clients/ctest0003", Object.assign({}, cur, { code: "M-AAAAA" }));
      assert.equal(r.status, 409);
    });
    await t("admin deletes client", async () => {
      assert.equal((await A("DELETE", "/api/clients/ctest0003")).status, 200);
      assert.equal((await A("GET", "/api/clients/ctest0003")).status, 404);
    });
    await t("PNL settings: seller forbidden, admin saves", async () => {
      assert.equal((await S("GET", "/api/settings/pnl")).status, 403);
      const g = await A("GET", "/api/settings/pnl"); assert.equal(g.body.buy, 7.5);
      const p = await A("PUT", "/api/settings/pnl", { plan1: 2000, start: "2026-01" });
      assert.equal(p.body.plan1, 2000); assert.equal(p.body.start, "2026-01");
    });
    await t("revoke -> seller loses access; reject deletes", async () => {
      const st = await A("GET", "/api/staff");
      const s = st.body.staff.find(x => x.login === "bobur");
      await A("POST", `/api/staff/${s.id}/revoke`);
      assert.equal((await S("GET", "/api/clients")).status, 403);
      await S2("POST", "/api/register", { name: "Spam", login: "spam", password: "secret1" });
      const st2 = await A("GET", "/api/staff");
      const sp = st2.body.pending.find(x => x.login === "spam");
      await A("POST", `/api/staff/${sp.id}/reject`);
      assert.equal((await S2("GET", "/api/me")).status, 401);
    });
    await t("admin creates staff with generated password; reset works", async () => {
      assert.equal((await S("POST", "/api/staff/create", { login: "x1", seller: "Bobur" })).status, 403);
      const r = await A("POST", "/api/staff/create", { name: "Sirojiddin", login: "siroj.p", seller: "Sirojiddin.P" });
      assert.equal(r.status, 200); assert.ok(r.body.password.length >= 8);
      assert.equal((await A("POST", "/api/staff/create", { login: "siroj.p", seller: "Bobur" })).status, 409);
      const U = jar();
      const l = await U("POST", "/api/login", { login: "siroj.p", password: r.body.password });
      assert.equal(l.body.role, "seller"); assert.equal(l.body.seller, "Sirojiddin.P");
      assert.equal((await U("GET", "/api/clients")).status, 200);
      const st = await A("GET", "/api/staff");
      const s = st.body.staff.find(x => x.login === "siroj.p");
      const rp = await A("POST", `/api/staff/${s.id}/reset-password`);
      assert.notEqual(rp.body.password, r.body.password);
      assert.equal((await U("GET", "/api/me")).status, 401);
      assert.equal((await jar()("POST", "/api/login", { login: "siroj.p", password: rp.body.password })).status, 200);
      assert.equal((await A("POST", `/api/staff/${s.id}/reset-password`, { password: "123" })).status, 400);
      const cp = await A("POST", `/api/staff/${s.id}/reset-password`, { password: "custom99" });
      assert.equal(cp.body.password, "custom99");
      assert.equal((await jar()("POST", "/api/login", { login: "siroj.p", password: "custom99" })).status, 200);
    });
    await t("logout clears session", async () => {
      await A("POST", "/api/logout");
      assert.equal((await A("GET", "/api/me")).status, 401);
    });
    console.log(`\n${ok} ta test o'tdi.`);
  } catch (e) {
    console.error("\nXATO:", e);
    process.exitCode = 1;
  } finally {
    srv.kill();
  }
})();
