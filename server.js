"use strict";

// Closing checklist server for DigitalOcean App Platform.
// Serves the app page and a small JSON API backed by PostgreSQL.

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT) || 8080;
const STORE_PIN = (process.env.STORE_PIN || "").trim();
const OWNER_PIN = (process.env.OWNER_PIN || "").trim();
const RESTAURANT_NAME = (process.env.RESTAURANT_NAME || "Schlotzsky's University").trim().slice(0, 80);
const TIMEZONE = validTimeZone(process.env.TIMEZONE) || "America/Chicago";
const ROLLOVER_HOUR = 5; // a close that runs past midnight still counts for the night before
const STAFF_DAYS = 180;
const OWNER_DAYS = 30;
const COOKIE = "cc_session";

const DEFAULT_TASKS = [
  { id: "k01", text: "Grill / flat-top scraped, cleaned & off" },
  { id: "k02", text: "Fryers off; oil filtered or changed" },
  { id: "k03", text: "Ovens & toasters off and wiped out" },
  { id: "k04", text: "Hot holding & steam wells cleaned and off" },
  { id: "k05", text: "Make-line inserts covered & stored; rail wiped" },
  { id: "k06", text: "All food covered, labeled & dated" },
  { id: "k07", text: "End-of-day waste logged" },
  { id: "k08", text: "Prep tables & cutting boards sanitized" },
  { id: "k09", text: "Walk-in at 41°F or below; door shut" },
  { id: "k10", text: "Freezer at 0°F or below; door shut" },
  { id: "k11", text: "Dishes put away; dish area cleaned" },
  { id: "k12", text: "Sinks scrubbed; sanitizer buckets dumped" },
  { id: "k13", text: "Floors swept & mopped; drains clear" },
  { id: "k14", text: "Trash out; dumpster lid closed" },
  { id: "d01", text: "Tables, chairs & booths wiped and sanitized" },
  { id: "d02", text: "High chairs & boosters wiped" },
  { id: "d03", text: "Condiment & napkin station cleaned & restocked" },
  { id: "d04", text: "Drink station: nozzles soaking, drip trays cleaned" },
  { id: "d05", text: "Tea & coffee brewers emptied, cleaned & off" },
  { id: "d06", text: "Front counter, POS & kiosks wiped" },
  { id: "d07", text: "Dining room trash emptied; new liners" },
  { id: "d08", text: "Restrooms cleaned & restocked" },
  { id: "d09", text: "Entry doors & glass wiped" },
  { id: "d10", text: "Floors swept & mopped" },
  { id: "p01", text: "Online & delivery apps closed for the night" },
  { id: "p02", text: "Headsets & delivery tablets on chargers" },
  { id: "p03", text: "Pickup shelf cleared & sanitized" },
  { id: "p04", text: "To-go bags, cups & lids restocked" },
  { id: "p05", text: "Window glass & sill cleaned; window locked" },
  { id: "p06", text: "Menu board & Open sign lights off" },
  { id: "p07", text: "Lane & lot checked for trash" },
  { id: "o01", text: "All orders closed out in POS" },
  { id: "o02", text: "Registers counted; end-of-day report run" },
  { id: "o03", text: "Tips counted & recorded" },
  { id: "o04", text: "Everyone clocked out" },
  { id: "o05", text: "Deposit prepped and in the safe" },
  { id: "o06", text: "Safe and office locked" },
  { id: "o07", text: "Notes left for opener (86s, repairs, call-outs)" },
  { id: "l01", text: "Building walked; no one left inside" },
  { id: "l02", text: "All gas & equipment off (double-checked)" },
  { id: "l03", text: "Faucets off; no running water" },
  { id: "l04", text: "Thermostat set for overnight" },
  { id: "l05", text: "Lights & music off (security lights on)" },
  { id: "l06", text: "Back & side doors locked" },
  { id: "l07", text: "Alarm set; front door locked" },
  { id: "l08", text: "Left with a coworker, never alone" }
];

function validTimeZone(tz) {
  if (!tz) return null;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return tz;
  } catch (e) {
    console.warn(`TIMEZONE "${tz}" isn't a valid time zone; using America/Chicago.`);
    return null;
  }
}

// ---------- Business day ----------
function businessDay(now = new Date()) {
  const parts = {};
  new Intl.DateTimeFormat("en-CA", {
    timeZone: TIMEZONE, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", hourCycle: "h23"
  }).formatToParts(now).forEach((p) => { parts[p.type] = p.value; });
  const d = new Date(Date.UTC(Number(parts.year), Number(parts.month) - 1, Number(parts.day)));
  if (Number(parts.hour) < ROLLOVER_HOUR) d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
}

// ---------- Sessions (signed cookie; changing either PIN signs everyone out) ----------
const SECRET = crypto.createHash("sha256")
  .update(["closing-checklist-v1", process.env.SESSION_SECRET || "", STORE_PIN, OWNER_PIN].join("\u0000"))
  .digest();

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return body + "." + mac;
}

function verify(token) {
  if (!token || typeof token !== "string") return null;
  const dot = token.indexOf(".");
  if (dot < 1) return null;
  const body = token.slice(0, dot);
  const mac = Buffer.from(token.slice(dot + 1));
  const expected = Buffer.from(crypto.createHmac("sha256", SECRET).update(body).digest("base64url"));
  if (mac.length !== expected.length || !crypto.timingSafeEqual(mac, expected)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")); } catch (e) { return null; }
  if (!payload || typeof payload.exp !== "number" || payload.exp < Date.now()) return null;
  if (payload.role !== "staff" && payload.role !== "owner") return null;
  return payload;
}

function readCookie(req, name) {
  const header = req.headers.cookie || "";
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { return null; }
    }
  }
  return null;
}

function setSession(req, res, role) {
  const days = role === "owner" ? OWNER_DAYS : STAFF_DAYS;
  const token = sign({ role, exp: Date.now() + days * 86400000 });
  const secure = req.secure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${days * 86400}${secure}`);
}

function clearSession(req, res) {
  const secure = req.secure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
}

function roleOf(req) {
  const s = verify(readCookie(req, COOKIE));
  return s ? s.role : null;
}

function pinMatches(input, pin) {
  if (!pin) return false;
  const a = crypto.createHash("sha256").update(String(input)).digest();
  const b = crypto.createHash("sha256").update(pin).digest();
  return crypto.timingSafeEqual(a, b);
}

// ---------- Slow down PIN guessing ----------
const WINDOW_MS = 15 * 60 * 1000;
const MAX_PER_IP = 8;
const MAX_TOTAL = 60;
const failures = new Map();
let totalFailures = [];

function clientIp(req) {
  return String(req.headers["do-connecting-ip"] || req.ip || "unknown");
}

function tooManyTries(ip) {
  const now = Date.now();
  totalFailures = totalFailures.filter((t) => now - t < WINDOW_MS);
  const mine = (failures.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  if (mine.length) failures.set(ip, mine); else failures.delete(ip);
  return mine.length >= MAX_PER_IP || totalFailures.length >= MAX_TOTAL;
}

function noteFailure(ip) {
  const now = Date.now();
  totalFailures.push(now);
  const mine = failures.get(ip) || [];
  mine.push(now);
  failures.set(ip, mine);
}

// ---------- Database ----------
let pool = null;
let databaseConfigProblem = null;
if (process.env.DATABASE_URL) {
  try {
    const url = new URL(process.env.DATABASE_URL);
    const host = url.hostname;
    const local = host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "";
    url.searchParams.delete("sslmode");
    pool = new Pool({
      connectionString: url.toString(),
      ssl: local ? false : { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });
    pool.on("error", (err) => console.error("Database connection error:", err.message));
  } catch (err) {
    databaseConfigProblem = "DATABASE_URL isn't a valid connection string.";
    console.error(databaseConfigProblem);
  }
} else {
  databaseConfigProblem = "DATABASE_URL isn't set.";
  console.warn("DATABASE_URL isn't set. Add it in DigitalOcean: ${db.DATABASE_URL}");
}

let schemaReady = null;
function ensureSchema() {
  if (!pool) {
    const err = new Error(databaseConfigProblem || "No database");
    err.code = "NO_DATABASE";
    return Promise.reject(err);
  }
  if (!schemaReady) {
    schemaReady = (async () => {
      await pool.query(`CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
      await pool.query(`CREATE TABLE IF NOT EXISTS checks (
        day DATE NOT NULL,
        task_id TEXT NOT NULL,
        checked_by TEXT,
        checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (day, task_id))`);
      await pool.query(`CREATE TABLE IF NOT EXISTS nights (
        day DATE PRIMARY KEY,
        done INTEGER NOT NULL,
        total INTEGER NOT NULL,
        missed JSONB NOT NULL DEFAULT '[]'::jsonb,
        people JSONB NOT NULL DEFAULT '[]'::jsonb,
        last_at TIMESTAMPTZ)`);
      await pool.query(
        "INSERT INTO app_settings (key, value) VALUES ('tasks', $1::jsonb) ON CONFLICT (key) DO NOTHING",
        [JSON.stringify(DEFAULT_TASKS)]
      );
      console.log("Database ready.");
    })().catch((err) => {
      schemaReady = null; // try again on the next request
      throw err;
    });
  }
  return schemaReady;
}

function databaseMessage(err) {
  if (err && err.code === "NO_DATABASE") {
    return "The app isn't connected to its database yet. In DigitalOcean, add the DATABASE_URL setting (see the guide).";
  }
  if (err && err.code === "42501") {
    return "The database is still being set up. Try again in a minute.";
  }
  return "Can't reach the database right now. Try again in a minute.";
}

const ID_RE = /^[A-Za-z0-9_-]{1,40}$/;
function newId() {
  return "t" + crypto.randomBytes(6).toString("hex");
}

function normalizeTasks(raw) {
  const out = [];
  const seen = new Set();
  (Array.isArray(raw) ? raw : []).slice(0, 300).forEach((t) => {
    if (!t || typeof t !== "object") return;
    const text = String(t.text == null ? "" : t.text).replace(/\s+/g, " ").trim().slice(0, 200);
    if (!text) return;
    const id = typeof t.id === "string" && ID_RE.test(t.id) && !seen.has(t.id) ? t.id : newId();
    seen.add(id);
    out.push({ id, text });
  });
  return out;
}

async function loadTasks(q) {
  const { rows } = await q.query("SELECT value FROM app_settings WHERE key = 'tasks'");
  return rows.length ? normalizeTasks(rows[0].value) : DEFAULT_TASKS.slice();
}

async function loadState(q, role) {
  const day = businessDay();
  const tasks = await loadTasks(q);
  const { rows } = await q.query(
    "SELECT task_id, checked_by, checked_at FROM checks WHERE day = $1",
    [day]
  );
  const checks = {};
  rows.forEach((r) => { checks[r.task_id] = { by: r.checked_by || null, at: r.checked_at }; });
  return { day, timezone: TIMEZONE, name: RESTAURANT_NAME, role, tasks, checks };
}

// Keeps one summary row per night up to date for the History tab.
async function recomputeNight(client, day, tasks) {
  const { rows } = await client.query(
    "SELECT task_id, checked_by, checked_at FROM checks WHERE day = $1",
    [day]
  );
  const byId = new Map(rows.map((r) => [r.task_id, r]));
  let done = 0;
  let lastAt = null;
  const missed = [];
  const people = [];
  tasks.forEach((t) => {
    const c = byId.get(t.id);
    if (c) {
      done++;
      if (c.checked_by && !people.includes(c.checked_by) && people.length < 20) people.push(c.checked_by);
      if (!lastAt || c.checked_at > lastAt) lastAt = c.checked_at;
    } else if (missed.length < 60) {
      missed.push(t.text);
    }
  });
  if (done === 0) {
    await client.query("DELETE FROM nights WHERE day = $1", [day]);
    return;
  }
  await client.query(
    `INSERT INTO nights (day, done, total, missed, people, last_at)
     VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)
     ON CONFLICT (day) DO UPDATE SET done = EXCLUDED.done, total = EXCLUDED.total,
       missed = EXCLUDED.missed, people = EXCLUDED.people, last_at = EXCLUDED.last_at`,
    [day, done, tasks.length, JSON.stringify(missed), JSON.stringify(people), lastAt]
  );
}

async function inNightTransaction(day, work) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", ["closing-night:" + day]);
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// ---------- App ----------
const app = express();
app.set("trust proxy", true);
app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
  );
  next();
});

app.get("/healthz", (req, res) => res.type("text").send("ok"));

app.use("/api", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

const pinsReady = () => Boolean(STORE_PIN && OWNER_PIN);

function requireRole(minimum) {
  return (req, res, next) => {
    const role = roleOf(req);
    if (!role) return res.status(401).json({ error: "locked", message: "Enter the PIN to continue." });
    if (minimum === "owner" && role !== "owner") {
      return res.status(403).json({ error: "owner_only", message: "Only the owner can change the list." });
    }
    req.role = role;
    next();
  };
}

async function requireDatabase(req, res, next) {
  try {
    await ensureSchema();
    next();
  } catch (err) {
    console.error("Database not ready:", err.message);
    res.status(503).json({ error: "database", message: databaseMessage(err) });
  }
}

app.get("/api/session", (req, res) => {
  res.json({
    name: RESTAURANT_NAME,
    timezone: TIMEZONE,
    day: businessDay(),
    role: pinsReady() ? roleOf(req) : null,
    setup: { pins: pinsReady(), database: Boolean(pool) }
  });
});

app.post("/api/login", (req, res) => {
  if (!pinsReady()) {
    return res.status(503).json({ error: "setup", message: "This app isn't finished setting up. Add STORE_PIN and OWNER_PIN in DigitalOcean." });
  }
  const ip = clientIp(req);
  if (tooManyTries(ip)) {
    return res.status(429).json({ error: "slow_down", message: "Too many wrong PINs. Wait 15 minutes and try again." });
  }
  const pin = String((req.body && req.body.pin) || "").trim().slice(0, 64);
  let role = null;
  if (pinMatches(pin, OWNER_PIN)) role = "owner";
  else if (pinMatches(pin, STORE_PIN)) role = "staff";
  if (!role) {
    noteFailure(ip);
    return res.status(401).json({ error: "wrong_pin", message: "That PIN didn't work. Try again." });
  }
  setSession(req, res, role);
  res.json({ role });
});

app.post("/api/logout", (req, res) => {
  clearSession(req, res);
  res.json({ ok: true });
});

app.get("/api/state", requireRole("staff"), requireDatabase, async (req, res) => {
  res.json(await loadState(pool, req.role));
});

app.post("/api/check", requireRole("staff"), requireDatabase, async (req, res) => {
  const body = req.body || {};
  const taskId = typeof body.taskId === "string" && ID_RE.test(body.taskId) ? body.taskId : null;
  if (!taskId || typeof body.checked !== "boolean") {
    return res.status(400).json({ error: "bad_request", message: "That change couldn't be read. Refresh and try again." });
  }
  const by = String(body.by == null ? "" : body.by).replace(/\s+/g, " ").trim().slice(0, 40) || null;
  const day = businessDay();
  const known = await inNightTransaction(day, async (client) => {
    const tasks = await loadTasks(client);
    if (!tasks.some((t) => t.id === taskId)) return false;
    if (body.checked) {
      await client.query(
        "INSERT INTO checks (day, task_id, checked_by) VALUES ($1, $2, $3) ON CONFLICT (day, task_id) DO NOTHING",
        [day, taskId, by]
      );
    } else {
      await client.query("DELETE FROM checks WHERE day = $1 AND task_id = $2", [day, taskId]);
    }
    await recomputeNight(client, day, tasks);
    return true;
  });
  if (!known) {
    return res.status(409).json({ error: "unknown_task", message: "That task isn't on the list anymore. The list has been refreshed." });
  }
  res.json(await loadState(pool, req.role));
});

app.get("/api/history", requireRole("staff"), requireDatabase, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT to_char(day, 'YYYY-MM-DD') AS day, done, total, missed, people, last_at
     FROM nights ORDER BY day DESC LIMIT 30`
  );
  res.json({
    today: businessDay(),
    timezone: TIMEZONE,
    nights: rows.map((r) => ({
      day: r.day,
      done: r.done,
      total: r.total,
      missed: Array.isArray(r.missed) ? r.missed : [],
      people: Array.isArray(r.people) ? r.people : [],
      lastAt: r.last_at
    }))
  });
});

app.put("/api/tasks", requireRole("owner"), requireDatabase, async (req, res) => {
  const tasks = normalizeTasks(req.body && req.body.tasks);
  const day = businessDay();
  await inNightTransaction(day, async (client) => {
    await client.query(
      `INSERT INTO app_settings (key, value, updated_at) VALUES ('tasks', $1::jsonb, now())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [JSON.stringify(tasks)]
    );
    await recomputeNight(client, day, tasks);
  });
  res.json(await loadState(pool, req.role));
});

app.use("/api", (req, res) => res.status(404).json({ error: "not_found", message: "Not found." }));

app.use(express.static(path.join(__dirname, "public"), {
  index: "index.html",
  setHeaders: (res) => res.setHeader("Cache-Control", "no-cache")
}));

app.use((req, res) => res.status(404).type("text").send("Not found"));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(500).json({ error: "server", message: "Something went wrong. Try again." });
});

app.listen(PORT, () => {
  console.log(`Closing checklist running on port ${PORT} (time zone ${TIMEZONE}).`);
  if (!pinsReady()) console.warn("STORE_PIN and OWNER_PIN aren't both set. Add them in DigitalOcean.");
  if (pool) ensureSchema().catch((err) => console.error("Database not ready yet:", err.message));
});
