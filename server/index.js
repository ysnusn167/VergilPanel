import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import { spawn } from "node:child_process";
import net from "node:net";
import Database from "better-sqlite3";
import QRCode from "qrcode";

const PORT = Number(process.env.PORT || 8080);
const HOST = "0.0.0.0";

const DATA_DIR = process.env.DATA_DIR || "/app/data";
const DB_PATH = `${DATA_DIR}/vergilpanel.db`;

const XRAY_BIN = process.env.XRAY_BIN || "/opt/xray/xray";
const XRAY_CONFIG = process.env.XRAY_CONFIG || "/app/xray/generated-config.json";

const XRAY_XHTTP_PORT = Number(process.env.XRAY_XHTTP_PORT || 10001);
const XRAY_WS_PORT = Number(process.env.XRAY_WS_PORT || 10002);

const XHTTP_PATH = process.env.XHTTP_PATH || "/xhttp";
const WS_PATH = process.env.WS_PATH || "/ws";

const VERSION = "0.8.1-fixed-paths";

/*
 * ============================================================
 * PUBLIC PATHS
 * ============================================================
 *
 * هر کاربر به صورت خودکار:
 * - یک مسیر XHTTP
 * - یک مسیر WebSocket
 *
 * دریافت می‌کند.
 *
 * مسیرها ثابت هستند و رندوم 16 کاراکتری نیستند.
 */

const XHTTP_PATHS = [
  "/xhttp-cdn",
  "/xhttp-sni",
  "/xhttp-game"
];

const WS_PATHS = [
  "/ws-cdn",
  "/ws-sni",
  "/ws-game"
];

let xrayProcess = null;
let stoppingXray = false;
let xrayRestarting = false;

const sessions = new Map();

await fs.mkdir(DATA_DIR, { recursive: true });
await fs.mkdir("/app/xray", { recursive: true });

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");

/*
 * ============================================================
 * DATABASE
 * ============================================================
 */

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 uuid TEXT UNIQUE NOT NULL,
 protocol TEXT NOT NULL DEFAULT 'vless',
 traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
 traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
 expires_at TEXT,
 status TEXT NOT NULL DEFAULT 'active',
 subscription_token TEXT UNIQUE,
 created_at TEXT NOT NULL
);
`);

function addColumnIfMissing(name, type) {
  const cols = db.prepare("PRAGMA table_info(users)").all();

  if (!cols.some(c => c.name === name)) {
    db.exec(`ALTER TABLE users ADD COLUMN ${name} ${type}`);
  }
}

addColumnIfMissing("xhttp_path", "TEXT");
addColumnIfMissing("ws_path", "TEXT");

/*
 * ============================================================
 * HELPERS
 * ============================================================
 */

const randomChoice = arr => arr[crypto.randomInt(arr.length)];

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("hex");
}

function nowIso() {
  return new Date().toISOString();
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function parseCookies(req) {
  const out = {};

  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");

    if (i < 0) continue;

    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();

    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
  }

  return out;
}

function getSession(req) {
  const cookies = parseCookies(req);

  if (!cookies.vergil_session) {
    return null;
  }

  return sessions.get(cookies.vergil_session) || null;
}

function redirect(res, location) {
  res.writeHead(302, {
    Location: location,
    "Cache-Control": "no-store"
  });

  res.end();
}

function sendHtml(res, html, status = 200) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store"
  });

  res.end(html);
}

function sendJson(res, data, status = 200) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });

  res.end(JSON.stringify(data));
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk;

      if (body.length > 1024 * 1024) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });

    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

async function readForm(req) {
  return new URLSearchParams(await readBody(req));
}

function requireAuth(req, res) {
  const session = getSession(req);

  if (!session) {
    redirect(res, "/login");
    return null;
  }

  return session;
}

function getPublicHost(req) {
  return String(
    req.headers["x-forwarded-host"] ||
    process.env.RAILWAY_PUBLIC_DOMAIN ||
    req.headers.host ||
    "localhost:8080"
  )
    .split(",")[0]
    .trim();
}

function getPublicOrigin(req) {
  const host = getPublicHost(req);

  if (
    host.startsWith("localhost") ||
    host.startsWith("127.0.0.1") ||
    host.includes(":8080")
  ) {
    return `http://${host}`;
  }

  return `https://${host}`;
}

function activeUsers() {
  return db
    .prepare(`
      SELECT *
      FROM users
      WHERE status='active'
      AND (
        expires_at IS NULL
        OR expires_at=''
        OR expires_at>?
      )
      ORDER BY id DESC
    `)
    .all(nowIso());
}

function allUsers() {
  return db
    .prepare("SELECT * FROM users ORDER BY id DESC")
    .all();
}

function getAdmin() {
  return db
    .prepare("SELECT * FROM admins ORDER BY id ASC LIMIT 1")
    .get();
}

/*
 * ============================================================
 * USER PATH ASSIGNMENT
 * ============================================================
 */

function ensureUserPaths(user) {
  let xhttpPath = user.xhttp_path;
  let wsPath = user.ws_path;

  if (!XHTTP_PATHS.includes(xhttpPath)) {
    xhttpPath = randomChoice(XHTTP_PATHS);
  }

  if (!WS_PATHS.includes(wsPath)) {
    wsPath = randomChoice(WS_PATHS);
  }

  if (
    xhttpPath !== user.xhttp_path ||
    wsPath !== user.ws_path
  ) {
    db
      .prepare(
        "UPDATE users SET xhttp_path=?, ws_path=? WHERE id=?"
      )
      .run(
        xhttpPath,
        wsPath,
        user.id
      );
  }

  return {
    ...user,
    xhttp_path: xhttpPath,
    ws_path: wsPath
  };
}

function ensureAllUserPaths() {
  const users = db
    .prepare("SELECT * FROM users")
    .all();

  for (const user of users) {
    ensureUserPaths(user);
  }
}

/*
 * ============================================================
 * XRAY CONFIG
 * ============================================================
 */

function generateXrayConfig() {
  const clients = activeUsers().map(user => ({
    id: user.uuid,
    email: user.username
  }));

  return {
    log: {
      loglevel: "warning"
    },

    inbounds: [
      {
        listen: "127.0.0.1",
        port: XRAY_XHTTP_PORT,

        protocol: "vless",

        settings: {
          clients,
          decryption: "none"
        },

        streamSettings: {
          network: "xhttp",
          security: "none",

          xhttpSettings: {
            path: XHTTP_PATH,
            mode: "auto"
          }
        }
      },

      {
        listen: "127.0.0.1",
        port: XRAY_WS_PORT,

        protocol: "vless",

        settings: {
          clients,
          decryption: "none"
        },

        streamSettings: {
          network: "websocket",
          security: "none",

          wsSettings: {
            path: WS_PATH
          }
        }
      }
    ],

    outbounds: [
      {
        protocol: "freedom"
      }
    ]
  };
}

async function writeXrayConfig() {
  const config = generateXrayConfig();

  await fs.writeFile(
    XRAY_CONFIG,
    JSON.stringify(config, null, 2),
    "utf8"
  );

  console.log(
    `⚙️ Xray config synced: ${activeUsers().length} active user(s)`
  );
}

function stopXray() {
  return new Promise(resolve => {
    if (!xrayProcess) {
      return resolve();
    }

    const process = xrayProcess;

    xrayProcess = null;

    const timeout = setTimeout(() => {
      try {
        process.kill("SIGKILL");
      } catch {}

      resolve();
    }, 3000);

    process.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });

    try {
      process.kill("SIGTERM");
    } catch {
      clearTimeout(timeout);
      resolve();
    }
  });
}

async function startXray() {
  await writeXrayConfig();

  console.log(`⚙️ Xray binary: ${XRAY_BIN}`);

  xrayProcess = spawn(
    XRAY_BIN,
    [
      "run",
      "-config",
      XRAY_CONFIG
    ],
    {
      stdio: [
        "ignore",
        "pipe",
        "pipe"
      ]
    }
  );

  xrayProcess.stdout.on("data", data => {
    process.stdout.write(`[XRAY] ${data}`);
  });

  xrayProcess.stderr.on("data", data => {
    process.stderr.write(`[XRAY] ${data}`);
  });

  xrayProcess.on("error", error => {
    console.error(
      "❌ Xray process error:",
      error
    );
  });

  xrayProcess.on(
    "exit",
    (code, signal) => {
      console.log(
        `⚠️ Xray exited. code=${code} signal=${signal}`
      );

      xrayProcess = null;

      if (
        !stoppingXray &&
        !xrayRestarting
      ) {
        setTimeout(
          () =>
            startXray().catch(
              error =>
                console.error(
                  "❌ Xray restart failed:",
                  error
                )
            ),
          1500
        );
      }
    }
  );
}

async function restartXray() {
  if (xrayRestarting) {
    return;
  }

  xrayRestarting = true;

  try {
    await stopXray();
    await startXray();
  } finally {
    xrayRestarting = false;
  }
}

/*
 * ============================================================
 * VLESS LINKS
 * ============================================================
 */

function makeVlessLinks(user, origin) {
  user = ensureUserPaths(user);

  const domain = new URL(origin).hostname;

  const xhttpParams = new URLSearchParams({
    encryption: "none",
    security: "tls",
    type: "xhttp",
    path: user.xhttp_path,
    host: domain,
    mode: "auto"
  });

  const wsParams = new URLSearchParams({
    encryption: "none",
    security: "tls",
    type: "ws",
    path: user.ws_path,
    host: domain
  });

  return {
    xhttp:
      `vless://${user.uuid}@${domain}:443?` +
      `${xhttpParams.toString()}#` +
      `${encodeURIComponent(user.username)}-XHTTP`,

    websocket:
      `vless://${user.uuid}@${domain}:443?` +
      `${wsParams.toString()}#` +
      `${encodeURIComponent(user.username)}-WS`
  };
}

/*
 * ============================================================
 * DUMMY CONFIG
 * ============================================================
 */

function makeDummyConfig() {
  return (
    "vless://00000000-0000-0000-0000-000000000000" +
    "@0.0.0.0:443" +
    "?encryption=none&security=none&type=tcp#" +
    encodeURIComponent(
      "ساخته شده توسط یاسین - پنل کاملاً رایگان و غیرقابل فروش است"
    )
  );
}

/*
 * ============================================================
 * SUBSCRIPTION
 * ============================================================
 */

function makeSubscription(user, origin) {
  const links = makeVlessLinks(
    user,
    origin
  );

  const lines = [
    links.xhttp,
    links.websocket,
    makeDummyConfig()
  ];

  return Buffer
    .from(
      lines.join("\n"),
      "utf8"
    )
    .toString("base64");
}

async function qrCode(text) {
  return QRCode.toDataURL(
    text,
    {
      width: 260,
      margin: 2,
      errorCorrectionLevel: "M"
    }
  );
}

/*
 * ============================================================
 * HTML LAYOUT
 * ============================================================
 */

function layout(title, body) {
  return `
<!doctype html>

<html lang="fa" dir="rtl">

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>
${escapeHtml(title)} — VergilPanel
</title>

<style>

:root{
  --bg:#03070d;
  --card:rgba(10,22,36,.82);
  --border:rgba(100,210,255,.16);
  --text:#eefaff;
  --muted:#7895a8;
  --blue:#38cfff;
  --cyan:#79e7ff;
  --green:#38e39a;
  --red:#ff5d73;
}

*{
  box-sizing:border-box;
}

body{
  margin:0;
  color:var(--text);
  font-family:Tahoma,Arial,sans-serif;

  background:
    radial-gradient(
      circle at 80% 5%,
      rgba(35,198,255,.16),
      transparent 28%
    ),
    linear-gradient(
      135deg,
      #02050a,
      #06111d 50%,
      #02070d
    );

  min-height:100vh;
}

a{
  color:inherit;
  text-decoration:none;
}

.container{
  width:min(1250px,100%);
  margin:auto;
  padding:24px;
}

.nav{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:15px;
  margin-bottom:24px;
}

.brand{
  font-size:23px;
  font-weight:1000;
}

.brand span,
.hero-title{
  color:var(--cyan);
}

.nav-right,
.actions{
  display:flex;
  align-items:center;
  gap:8px;
}

.btn{
  display:inline-flex;
  align-items:center;
  justify-content:center;

  border:1px solid var(--border);

  background:
    rgba(12,28,44,.8);

  color:var(--text);

  padding:10px 15px;
  border-radius:11px;

  cursor:pointer;
  font-size:13px;
}

.btn.primary{
  color:#001018;

  background:
    linear-gradient(
      135deg,
      var(--cyan),
      var(--blue)
    );

  font-weight:900;
}

.btn.danger{
  color:#ff9aa8;
  background:rgba(91,18,32,.45);
}

.grid{
  display:grid;
  grid-template-columns:
    repeat(4,1fr);

  gap:15px;
}

.card,
.hero{
  background:
    linear-gradient(
      145deg,
      rgba(27,68,94,.15),
      rgba(5,13,22,.88)
    );

  border:1px solid var(--border);

  border-radius:18px;

  padding:20px;

  box-shadow:
    0 20px 60px
    rgba(0,0,0,.25);
}

.hero{
  margin-bottom:18px;
}

h1,
h2,
h3{
  margin-top:0;
}

.muted{
  color:var(--muted);
}

.stat{
  font-size:28px;
  font-weight:1000;
}

table{
  width:100%;
  border-collapse:collapse;
}

th,
td{
  padding:13px 10px;
  border-bottom:
    1px solid
    rgba(255,255,255,.06);

  text-align:right;
}

input,
select{
  width:100%;

  background:#07131f;

  border:
    1px solid
    rgba(110,210,255,.18);

  color:white;

  padding:12px;

  border-radius:10px;

  outline:none;
}

label{
  display:block;
  margin-bottom:7px;
  color:#9bb3c2;
  font-size:13px;
}

.form-grid{
  display:grid;
  grid-template-columns:
    repeat(2,1fr);

  gap:15px;
}

.full{
  grid-column:1/-1;
}

.notice{
  padding:14px;

  border:
    1px solid
    rgba(88,213,255,.15);

  background:
    rgba(15,42,58,.35);

  border-radius:13px;

  margin:15px 0;
}

.config{
  direction:ltr;
  text-align:left;

  white-space:pre-wrap;
  word-break:break-all;

  background:#02060a;

  border:
    1px solid
    rgba(255,255,255,.06);

  padding:14px;

  border-radius:12px;

  color:#9deaff;

  font-family:
    ui-monospace,
    SFMono-Regular,
    Menlo,
    monospace;

  font-size:12px;
}

.qr-grid{
  display:grid;
  grid-template-columns:
    repeat(2,1fr);

  gap:15px;
}

.qr-card{
  text-align:center;

  background:
    rgba(255,255,255,.025);

  border:
    1px solid
    rgba(255,255,255,.06);

  border-radius:15px;

  padding:15px;
}

.qr-card img{
  max-width:260px;
  width:100%;
  background:white;
  padding:8px;
  border-radius:12px;
}

.badge{
  display:inline-block;

  padding:5px 9px;

  border-radius:99px;

  font-size:11px;

  background:
    rgba(56,227,154,.12);

  color:var(--green);
}

.badge.off{
  background:
    rgba(255,93,115,.12);

  color:var(--red);
}

.login{
  min-height:100vh;

  display:flex;
  align-items:center;
  justify-content:center;

  padding:20px;
}

.login-card{
  width:min(430px,100%);
}

.footer{
  text-align:center;
  margin-top:30px;
  color:var(--muted);
  font-size:12px;
}

@media(max-width:900px){
  .grid{
    grid-template-columns:
      repeat(2,1fr);
  }
}

@media(max-width:600px){
  .container{
    padding:14px;
  }

  .grid,
  .form-grid,
  .qr-grid{
    grid-template-columns:1fr;
  }

  .nav{
    align-items:flex-start;
    flex-direction:column;
  }

  table{
    font-size:12px;
  }

  th:nth-child(3),
  td:nth-child(3){
    display:none;
  }
}

</style>

</head>

<body>

${body}

</body>

</html>
`;
}

/*
 * ============================================================
 * LOGIN PAGE
 * ============================================================
 */

function loginPage(error = "") {
  return layout(
    "Login",
    `
<div class="login">

<div class="card login-card">

<h1>
⚔️ VergilPanel
</h1>

<p class="muted">
مدیریت Xray / VLESS
</p>

${error ? `
<div class="notice">
❌ ${escapeHtml(error)}
</div>
` : ""}

<form
  method="POST"
  action="/login"
>

<div style="margin-bottom:14px">

<label>
نام کاربری
</label>

<input
  name="username"
  autocomplete="username"
  required
>

</div>

<div style="margin-bottom:15px">

<label>
رمز عبور
</label>

<input
  type="password"
  name="password"
  autocomplete="current-password"
  required
>

</div>

<button
  class="btn primary"
  style="width:100%"
>
ورود
</button>

</form>

<div class="footer">
ساخته شده توسط یاسین
<br>
پنل کاملاً رایگان و غیرقابل فروش است
</div>

</div>

</div>
`
  );
}

/*
 * ============================================================
 * DASHBOARD
 * ============================================================
 */

function dashboardPage() {
  const users = allUsers();

  const active = users.filter(
    u => u.status === "active"
  ).length;

  return layout(
    "Dashboard",
    `
<div class="container">

<div class="nav">

<div class="brand">
⚔️ Vergil<span>Panel</span>
</div>

<div class="nav-right">

<a
  class="btn"
  href="/settings"
>
⚙️ تنظیمات
</a>

<a
  class="btn danger"
  href="/logout"
>
خروج
</a>

</div>

</div>

<div class="hero">

<h1 class="hero-title">
داشبورد مدیریت
</h1>

<p class="muted">
مدیریت کاربران VLESS و Xray
</p>

<div class="actions">

<a
  class="btn primary"
  href="/users/new"
>
➕ ساخت کاربر
</a>

</div>

</div>

<div class="grid">

<div class="card">

<div class="muted">
کل کاربران
</div>

<div class="stat">
${users.length}
</div>

</div>

<div class="card">

<div class="muted">
کاربران فعال
</div>

<div class="stat">
${active}
</div>

</div>

<div class="card">

<div class="muted">
XHTTP
</div>

<div class="stat">
3
</div>

</div>

<div class="card">

<div class="muted">
WebSocket
</div>

<div class="stat">
3
</div>

</div>

</div>

<br>

<div class="card">

<h2>
👥 کاربران
</h2>

<div style="overflow:auto">

<table>

<thead>

<tr>

<th>
نام کاربری
</th>

<th>
وضعیت
</th>

<th>
XHTTP
</th>

<th>
WebSocket
</th>

<th>
عملیات
</th>

</tr>

</thead>

<tbody>

${
  users.length
    ? users.map(user => `
<tr>

<td>
<strong>
${escapeHtml(user.username)}
</strong>
</td>

<td>

<span
  class="badge ${
    user.status === "active"
      ? ""
      : "off"
  }"
>
${
  user.status === "active"
    ? "فعال"
    : "غیرفعال"
}
</span>

</td>

<td dir="ltr">
${escapeHtml(user.xhttp_path || "-")}
</td>

<td dir="ltr">
${escapeHtml(user.ws_path || "-")}
</td>

<td>

<div class="actions">

<a
  class="btn"
  href="/users/config?id=${user.id}"
>
کانفیگ
</a>

<form
  method="POST"
  action="/users/toggle"
  style="display:inline"
>

<input
  type="hidden"
  name="id"
  value="${user.id}"
>

<button
  class="btn"
  type="submit"
>
${user.status === "active"
  ? "غیرفعال"
  : "فعال"}
</button>

</form>

<form
  method="POST"
  action="/users/delete"
  style="display:inline"
  onsubmit="return confirm('کاربر حذف شود؟')"
>

<input
  type="hidden"
  name="id"
  value="${user.id}"
>

<button
  class="btn danger"
  type="submit"
>
حذف
</button>

</form>

</div>

</td>

</tr>
`).join("")
    : `
<tr>

<td
  colspan="5"
  style="text-align:center"
  class="muted"
>
هنوز کاربری ساخته نشده است.
</td>

</tr>
`
}

</tbody>

</table>

</div>

</div>

<div class="footer">

<div>
ساخته شده توسط یاسین
</div>

<div>
پنل کاملاً رایگان و غیرقابل فروش است
</div>

<div>
به یاد زنده‌یاد علی نور 🖤
</div>

</div>

</div>
`
  );
}

/*
 * ============================================================
 * SETTINGS
 * ============================================================
 */

function settingsPage(message = "", error = "") {
  const admin = getAdmin();

  return layout(
    "Settings",
    `
<div class="container">

<div class="nav">

<div class="brand">
⚔️ VergilPanel
</div>

<div class="nav-right">

<a
  class="btn"
  href="/dashboard"
>
داشبورد
</a>

<a
  class="btn danger"
  href="/logout"
>
خروج
</a>

</div>

</div>

<div class="card">

<h1>
⚙️ تنظیمات
</h1>

${
  message
    ? `
<div class="notice">
✅ ${escapeHtml(message)}
</div>
`
    : ""
}

${
  error
    ? `
<div class="notice">
❌ ${escapeHtml(error)}
</div>
`
    : ""
}

<form
  method="POST"
  action="/settings"
>

<div class="form-grid">

<div>

<label>
نام کاربری ادمین
</label>

<input
  name="username"
  value="${escapeHtml(admin?.username || "admin")}"
  required
>

</div>

<div>

<label>
رمز عبور جدید
</label>

<input
  type="password"
  name="password"
>

</div>

<div>

<label>
تکرار رمز عبور
</label>

<input
  type="password"
  name="password_confirm"
>

</div>

</div>

<br>

<button
  class="btn primary"
>
ذخیره تنظیمات
</button>

</form>

</div>

</div>
`
  );
}

/*
 * ============================================================
 * NEW USER
 * ============================================================
 */

function newUserPage(error = "") {
  return layout(
    "New User",
    `
<div class="container">

<div class="nav">

<div class="brand">
⚔️ VergilPanel
</div>

<a
  class="btn"
  href="/dashboard"
>
بازگشت
</a>

</div>

<div class="card">

<h1>
➕ ساخت کاربر
</h1>

${
  error
    ? `
<div class="notice">
❌ ${escapeHtml(error)}
</div>
`
    : ""
}

<div class="notice">

<strong>
انتخاب مسیرها کاملاً خودکار است.
</strong>

<br><br>

XHTTP:

<code dir="ltr">
/xhttp-cdn
</code>

&nbsp;|&nbsp;

<code dir="ltr">
/xhttp-sni
</code>

&nbsp;|&nbsp;

<code dir="ltr">
/xhttp-game
</code>

<br><br>

WebSocket:

<code dir="ltr">
/ws-cdn
</code>

&nbsp;|&nbsp;

<code dir="ltr">
/ws-sni
</code>

&nbsp;|&nbsp;

<code dir="ltr">
/ws-game
</code>

</div>

<form
  method="POST"
  action="/users/new"
>

<div class="form-grid">

<div>

<label>
نام کاربری
</label>

<input
  name="username"
  placeholder="مثلاً user1"
  required
>

</div>

<div>

<label>
حجم ترافیک به GB
</label>

<input
  type="number"
  name="traffic_limit"
  value="0"
  min="0"
>

</div>

<div>

<label>
تاریخ انقضا
</label>

<input
  type="datetime-local"
  name="expires_at"
>

</div>

</div>

<br>

<button
  class="btn primary"
>
ساخت کاربر
</button>

</form>

</div>

</div>
`
  );
}

/*
 * ============================================================
 * USER CONFIG PAGE
 * ============================================================
 */

async function configPage(req, user) {
  user = ensureUserPaths(user);

  const origin = getPublicOrigin(req);

  const links = makeVlessLinks(
    user,
    origin
  );

  const subscription =
    makeSubscription(
      user,
      origin
    );

  const subscriptionUrl =
    `${origin}/sub/${user.subscription_token}`;

  const subscriptionQr =
    await qrCode(subscriptionUrl);

  const xhttpQr =
    await qrCode(links.xhttp);

  const wsQr =
    await qrCode(links.websocket);

  return layout(
    "User Config",
    `
<div class="container">

<div class="nav">

<div class="brand">
⚔️ VergilPanel
</div>

<div class="nav-right">

<a
  class="btn"
  href="/dashboard"
>
داشبورد
</a>

</div>

</div>

<div class="card">

<h1>
👤 ${escapeHtml(user.username)}
</h1>

<p class="muted">
VLESS · XHTTP + WebSocket
</p>

<div class="notice">

<strong>
📡 Subscription
</strong>

<pre class="config">${escapeHtml(subscriptionUrl)}</pre>

<button
  class="btn primary"
  onclick='copyText(${JSON.stringify(subscriptionUrl)})'
>
📋 کپی Subscription URL
</button>

</div>

<div class="qr-grid">

<div class="qr-card">

<h3>
📡 Subscription QR
</h3>

<img
  src="${subscriptionQr}"
>

</div>

<div class="qr-card">

<h3>
🔥 XHTTP QR
</h3>

<img
  src="${xhttpQr}"
>

</div>

</div>

<br>

<h2>
🚀 VLESS + XHTTP
</h2>

<div class="notice">

<b>
Path:
</b>

<span dir="ltr">
${escapeHtml(user.xhttp_path)}
</span>

</div>

<pre class="config">${escapeHtml(links.xhttp)}</pre>

<button
  class="btn"
  onclick='copyText(${JSON.stringify(links.xhttp)})'
>
📋 Copy XHTTP
</button>

<br><br>

<h2>
🌐 VLESS + WebSocket
</h2>

<div class="notice">

<b>
Path:
</b>

<span dir="ltr">
${escapeHtml(user.ws_path)}
</span>

</div>

<pre class="config">${escapeHtml(links.websocket)}</pre>

<button
  class="btn"
  onclick='copyText(${JSON.stringify(links.websocket)})'
>
📋 Copy WebSocket
</button>

<br><br>

<div class="qr-grid">

<div class="qr-card">

<h3>
🔥 XHTTP
</h3>

<img
  src="${xhttpQr}"
>

</div>

<div class="qr-card">

<h3>
🌐 WebSocket
</h3>

<img
  src="${wsQr}"
>

</div>

</div>

<div class="notice">

<strong>
ساخته شده توسط یاسین
</strong>

<br>

پنل کاملاً رایگان و غیرقابل فروش است

<br><br>

<strong>
به یاد زنده‌یاد علی نور 🖤
</strong>

</div>

<h2>
🆔 UUID
</h2>

<pre class="config">${escapeHtml(user.uuid)}</pre>

<h2>
📡 Subscription
</h2>

<pre class="config">${escapeHtml(subscription)}</pre>

</div>

</div>

<script>

async function copyText(text){

  try{

    await navigator.clipboard.writeText(text);

    alert("کپی شد ✅");

  }catch{

    prompt(
      "متن را کپی کنید:",
      text
    );

  }

}

</script>
`
  );
}

/*
 * ============================================================
 * ADMIN
 * ============================================================
 */

function ensureDefaultAdmin() {

  const username =
    String(
      process.env.ADMIN_USERNAME ||
      "admin"
    ).trim();

  const password =
    String(
      process.env.ADMIN_PASSWORD ||
      "admin"
    );

  const admin = getAdmin();

  if (!admin) {

    db.prepare(
      `
      INSERT INTO admins(
        username,
        password_hash,
        created_at
      )
      VALUES(?,?,?)
      `
    ).run(
      username,
      hashPassword(password),
      nowIso()
    );

    console.log(
      `👤 Default admin created: ${username}`
    );

  } else {

    console.log(
      `👤 Admin ready: ${admin.username}`
    );

  }
}

function authenticate(
  username,
  password
) {

  const admin =
    db.prepare(
      "SELECT * FROM admins WHERE username=?"
    ).get(username);

  return Boolean(
    admin &&
    admin.password_hash ===
      hashPassword(password)
  );
}

/*
 * ============================================================
 * CREATE USER
 * ============================================================
 */

async function createUser(form) {

  const username =
    String(
      form.get("username") || ""
    ).trim();

  if (!username) {
    throw new Error(
      "نام کاربری الزامی است."
    );
  }

  if (
    db
      .prepare(
        "SELECT id FROM users WHERE username=?"
      )
      .get(username)
  ) {
    throw new Error(
      "این نام کاربری قبلاً وجود دارد."
    );
  }

  let expiresAt = null;

  const expiry =
    String(
      form.get("expires_at") || ""
    ).trim();

  if (expiry) {

    const date =
      new Date(expiry);

    if (
      Number.isNaN(
        date.getTime()
      )
    ) {
      throw new Error(
        "تاریخ انقضا نامعتبر است."
      );
    }

    expiresAt =
      date.toISOString();
  }

  const limit =
    Number(
      form.get("traffic_limit") || 0
    );

  const xhttpPath =
    randomChoice(XHTTP_PATHS);

  const wsPath =
    randomChoice(WS_PATHS);

  const token =
    randomToken(32);

  const uuid =
    crypto.randomUUID();

  const result =
    db.prepare(
      `
      INSERT INTO users(
        username,
        uuid,
        protocol,
        traffic_limit_bytes,
        traffic_used_bytes,
        expires_at,
        status,
        subscription_token,
        created_at,
        xhttp_path,
        ws_path
      )

      VALUES(
        ?,
        ?,
        'vless',
        ?,
        0,
        ?,
        'active',
        ?,
        ?,
        ?,
        ?
      )
      `
    ).run(
      username,
      uuid,
      Number.isFinite(limit)
        ? limit
        : 0,
      expiresAt,
      token,
      nowIso(),
      xhttpPath,
      wsPath
    );

  await restartXray();

  return db
    .prepare(
      "SELECT * FROM users WHERE id=?"
    )
    .get(
      result.lastInsertRowid
    );
}

/*
 * ============================================================
 * DELETE / TOGGLE
 * ============================================================
 */

async function deleteUser(id) {

  db
    .prepare(
      "DELETE FROM users WHERE id=?"
    )
    .run(Number(id));

  await restartXray();
}

async function toggleUser(id) {

  const user =
    db
      .prepare(
        "SELECT * FROM users WHERE id=?"
      )
      .get(Number(id));

  if (!user) {
    throw new Error(
      "User not found."
    );
  }

  db
    .prepare(
      "UPDATE users SET status=? WHERE id=?"
    )
    .run(
      user.status === "active"
        ? "disabled"
        : "active",
      Number(id)
    );

  await restartXray();
}

/*
 * ============================================================
 * UPDATE ADMIN
 * ============================================================
 */

function updateAdmin(
  username,
  password
) {

  const admin =
    getAdmin();

  const newUsername =
    String(
      username || ""
    ).trim();

  if (!newUsername) {
    throw new Error(
      "نام کاربری نمی‌تواند خالی باشد."
    );
  }

  if (
    password &&
    String(password).length < 4
  ) {
    throw new Error(
      "رمز عبور باید حداقل 4 کاراکتر باشد."
    );
  }

  if (password) {

    db.prepare(
      `
      UPDATE admins
      SET username=?,
          password_hash=?
      WHERE id=?
      `
    ).run(
      newUsername,
      hashPassword(password),
      admin.id
    );

  } else {

    db.prepare(
      `
      UPDATE admins
      SET username=?
      WHERE id=?
      `
    ).run(
      newUsername,
      admin.id
    );

  }
}

/*
 * ============================================================
 * HTTP PROXY
 * ============================================================
 */

function proxyHttpToXray(
  req,
  res
) {

  const target =
    new URL(
      req.url,
      `http://${req.headers.host || "localhost"}`
    );

  /*
   * مسیر عمومی:
   *
   * /xhttp-cdn
   * /xhttp-sni
   * /xhttp-game
   *
   * تبدیل می‌شود به:
   *
   * /xhttp
   */

  target.pathname =
    XHTTP_PATH;

  const proxy =
    http.request(
      {
        hostname: "127.0.0.1",

        port:
          XRAY_XHTTP_PORT,

        path:
          target.pathname +
          target.search,

        method:
          req.method,

        headers: {
          ...req.headers,

          host:
            `127.0.0.1:${XRAY_XHTTP_PORT}`
        }
      },

      upstream => {

        res.writeHead(
          upstream.statusCode || 502,
          upstream.headers
        );

        upstream.pipe(res);
      }
    );

  proxy.on(
    "error",
    error => {

      console.error(
        "HTTP proxy error:",
        error
      );

      if (!res.headersSent) {

        res.writeHead(
          502,
          {
            "Content-Type":
              "text/plain"
          }
        );

      }

      res.end(
        "Bad Gateway"
      );
    }
  );

  req.pipe(proxy);
}

/*
 * ============================================================
 * WEBSOCKET PROXY
 * ============================================================
 */

function proxyWebSocket(
  req,
  clientSocket,
  head
) {

  const upstream =
    net.connect(
      {
        host: "127.0.0.1",
        port: XRAY_WS_PORT
      }
    );

  upstream.on(
    "connect",
    () => {

      const url =
        new URL(
          req.url,
          `http://${req.headers.host || "localhost"}`
        );

      /*
       * مسیر عمومی:
       *
       * /ws-cdn
       * /ws-sni
       * /ws-game
       *
       * تبدیل می‌شود به:
       *
       * /ws
       */

      url.pathname =
        WS_PATH;

      const lines = [
        `${req.method} ${url.pathname}${url.search} HTTP/${req.httpVersion}`
      ];

      for (
        const [key, value]
        of Object.entries(req.headers)
      ) {

        if (Array.isArray(value)) {

          for (const item of value) {

            lines.push(
              `${key}: ${item}`
            );

          }

        } else {

          lines.push(
            `${key}: ${value}`
          );

        }
      }

      lines.push(
        "",
        ""
      );

      upstream.write(
        lines.join("\r\n")
      );

      if (head?.length) {
        upstream.write(head);
      }

      clientSocket.pipe(
        upstream
      );

      upstream.pipe(
        clientSocket
      );
    }
  );

  upstream.on(
    "error",
    error => {

      console.error(
        "WebSocket proxy error:",
        error
      );

      try {
        clientSocket.destroy();
      } catch {}

    }
  );

  clientSocket.on(
    "error",
    () => {

      try {
        upstream.destroy();
      } catch {}

    }
  );

  clientSocket.on(
    "close",
    () => {

      try {
        upstream.destroy();
      } catch {}

    }
  );
}

/*
 * ============================================================
 * SUBSCRIPTION RESPONSE
 * ============================================================
 */

async function subscriptionResponse(
  req,
  res,
  token
) {

  const user =
    db
      .prepare(
        "SELECT * FROM users WHERE subscription_token=?"
      )
      .get(token);

  if (!user) {

    return sendJson(
      res,
      {
        ok: false,
        error:
          "Subscription not found."
      },
      404
    );

  }

  if (
    user.status !== "active"
  ) {

    return sendJson(
      res,
      {
        ok: false,
        error:
          "Subscription disabled."
      },
      403
    );

  }

  if (
    user.expires_at &&
    user.expires_at <= nowIso()
  ) {

    return sendJson(
      res,
      {
        ok: false,
        error:
          "Subscription expired."
      },
      403
    );

  }

  res.writeHead(
    200,
    {
      "Content-Type":
        "text/plain; charset=utf-8",

      "Cache-Control":
        "no-store"
    }
  );

  res.end(
    makeSubscription(
      ensureUserPaths(user),
      getPublicOrigin(req)
    )
  );
}

/*
 * ============================================================
 * MAIN HTTP HANDLER
 * ============================================================
 */

async function handleRequest(
  req,
  res
) {

  try {

    const url =
      new URL(
        req.url,
        `http://${req.headers.host || "localhost"}`
      );

    const path =
      url.pathname;

    /*
     * XHTTP PUBLIC PATHS
     */

    if (
      XHTTP_PATHS.includes(path) ||
      XHTTP_PATHS.some(
        x => path.startsWith(`${x}/`)
      )
    ) {

      proxyHttpToXray(
        req,
        res
      );

      return;
    }

    /*
     * SUBSCRIPTION
     */

    if (
      path.startsWith("/sub/")
    ) {

      await subscriptionResponse(
        req,
        res,
        path.slice(5)
      );

      return;
    }

    /*
     * HEALTH
     */

    if (
      path === "/health"
    ) {

      return sendJson(
        res,
        {
          ok: true,

          panel:
            VERSION,

          xray:
            Boolean(
              xrayProcess &&
              !xrayProcess.killed
            ),

          transports: [
            "xhttp",
            "websocket"
          ],

          xhttp_paths:
            XHTTP_PATHS,

          ws_paths:
            WS_PATHS,

          bind:
            HOST
        }
      );

    }

    /*
     * LOGIN GET
     */

    if (
      path === "/login" &&
      req.method === "GET"
    ) {

      return getSession(req)
        ? redirect(
            res,
            "/dashboard"
          )
        : sendHtml(
            res,
            loginPage()
          );

    }

    /*
     * LOGIN POST
     */

    if (
      path === "/login" &&
      req.method === "POST"
    ) {

      const form =
        await readForm(req);

      const username =
        String(
          form.get("username") || ""
        ).trim();

      const password =
        String(
          form.get("password") || ""
        );

      if (
        !authenticate(
          username,
          password
        )
      ) {

        return sendHtml(
          res,
          loginPage(
            "نام کاربری یا رمز عبور اشتباه است."
          ),
          401
        );

      }

      const token =
        randomToken(32);

      sessions.set(
        token,
        {
          username,
          createdAt: Date.now()
        }
      );

      const admin =
        getAdmin();

      const defaultLogin =
        admin &&
        username === "admin" &&
        password === "admin";

      res.writeHead(
        302,
        {
          Location:
            defaultLogin
              ? "/settings"
              : "/dashboard",

          "Set-Cookie":
            `vergil_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Secure`
        }
      );

      return res.end();
    }

    /*
     * LOGOUT
     */

    if (
      path === "/logout"
    ) {

      const cookies =
        parseCookies(req);

      if (
        cookies.vergil_session
      ) {

        sessions.delete(
          cookies.vergil_session
        );

      }

      res.writeHead(
        302,
        {
          Location:
            "/login",

          "Set-Cookie":
            "vergil_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure"
        }
      );

      return res.end();
    }

    /*
     * AUTH
     */

    if (
      !requireAuth(
        req,
        res
      )
    ) {
      return;
    }

    /*
     * DASHBOARD
     */

    if (
      path === "/" ||
      path === "/dashboard"
    ) {

      return sendHtml(
        res,
        dashboardPage()
      );

    }

    /*
     * SETTINGS GET
     */

    if (
      path === "/settings" &&
      req.method === "GET"
    ) {

      return sendHtml(
        res,
        settingsPage()
      );

    }

    /*
     * SETTINGS POST
     */

    if (
      path === "/settings" &&
      req.method === "POST"
    ) {

      try {

        const form =
          await readForm(req);

        const password =
          String(
            form.get("password") || ""
          );

        const confirmPassword =
          String(
            form.get("password_confirm") || ""
          );

        if (
          password &&
          password !== confirmPassword
        ) {

          throw new Error(
            "رمزهای عبور یکسان نیستند."
          );

        }

        updateAdmin(
          String(
            form.get("username") || ""
          ),
          password
        );

        sessions.clear();

        redirect(
          res,
          "/login"
        );

      } catch (error) {

        sendHtml(
          res,
          settingsPage(
            "",
            error?.message ||
              "خطا"
          ),
          400
        );

      }

      return;
    }

    /*
     * NEW USER GET
     */

    if (
      path === "/users/new" &&
      req.method === "GET"
    ) {

      return sendHtml(
        res,
        newUserPage()
      );

    }

    /*
     * NEW USER POST
     */

    if (
      path === "/users/new" &&
      req.method === "POST"
    ) {

      try {

        const user =
          await createUser(
            await readForm(req)
          );

        console.log(
          `👤 User created: ${user.username} | ${user.xhttp_path} | ${user.ws_path}`
        );

        redirect(
          res,
          `/users/config?id=${user.id}`
        );

      } catch (error) {

        sendHtml(
          res,
          newUserPage(
            error?.message ||
              "خطا در ساخت کاربر"
          ),
          400
        );

      }

      return;
    }

    /*
     * USER CONFIG
     */

    if (
      path === "/users/config" &&
      req.method === "GET"
    ) {

      const id =
        Number(
          url.searchParams.get("id")
        );

      const user =
        db
          .prepare(
            "SELECT * FROM users WHERE id=?"
          )
          .get(id);

      if (!user) {

        return sendHtml(
          res,
          layout(
            "404",
            `
<div class="container">

<div class="card">

<h1>
کاربر پیدا نشد
</h1>

<a
  class="btn"
  href="/dashboard"
>
داشبورد
</a>

</div>

</div>
`
          ),
          404
        );

      }

      return sendHtml(
        res,
        await configPage(
          req,
          user
        )
      );
    }

    /*
     * TOGGLE USER
     */

    if (
      path === "/users/toggle" &&
      req.method === "POST"
    ) {

      try {

        const form =
          await readForm(req);

        await toggleUser(
          form.get("id")
        );

      } catch (error) {

        console.error(
          error
        );

      }

      return redirect(
        res,
        "/dashboard"
      );
    }

    /*
     * DELETE USER
     */

    if (
      path === "/users/delete" &&
      req.method === "POST"
    ) {

      try {

        const form =
          await readForm(req);

        await deleteUser(
          form.get("id")
        );

      } catch (error) {

        console.error(
          error
        );

      }

      return redirect(
        res,
        "/dashboard"
      );
    }

    /*
     * 404
     */

    return sendHtml(
      res,
      layout(
        "404",
        `
<div class="container">

<div class="card">

<h1>
404
</h1>

<a
  class="btn"
  href="/dashboard"
>
بازگشت
</a>

</div>

</div>
`
      ),
      404
    );

  } catch (error) {

    console.error(
      "Unhandled server error:",
      error
    );

    if (!res.headersSent) {

      sendJson(
        res,
        {
          ok: false,
          error:
            "Internal Server Error"
        },
        500
      );

    }

  }
}

/*
 * ============================================================
 * SERVER
 * ============================================================
 */

const server =
  http.createServer(
    handleRequest
  );

/*
 * ============================================================
 * WEBSOCKET UPGRADE
 * ============================================================
 */

server.on(
  "upgrade",
  (
    req,
    socket,
    head
  ) => {

    try {

      const url =
        new URL(
          req.url,
          `http://${req.headers.host || "localhost"}`
        );

      const path =
        url.pathname;

      if (
        WS_PATHS.includes(path) ||
        WS_PATHS.some(
          x => path.startsWith(`${x}/`)
        )
      ) {

        proxyWebSocket(
          req,
          socket,
          head
        );

        return;
      }

      socket.destroy();

    } catch {

      socket.destroy();

    }
  }
);

/*
 * ============================================================
 * STARTUP
 * ============================================================
 */

ensureDefaultAdmin();

ensureAllUserPaths();

await startXray();

server.listen(
  PORT,
  HOST,
  () => {

    console.log(
      `⚔️ VergilPanel ${VERSION} running on ${HOST}:${PORT}`
    );

    console.log(
      `👤 Login: admin / admin`
    );

    console.log(
      `🌐 WS public paths: ${WS_PATHS.join(", ")}`
    );

    console.log(
      `📡 XHTTP public paths: ${XHTTP_PATHS.join(", ")}`
    );

    console.log(
      `🌍 Bind address: ${HOST}`
    );

    console.log(
      `🖤 به یاد زنده‌یاد علی نور`
    );

    console.log(
      `💙 ساخته شده توسط یاسین | پنل کاملاً رایگان و غیرقابل فروش است`
    );
  }
);

/*
 * ============================================================
 * SHUTDOWN
 * ============================================================
 */

async function shutdown(signal) {

  console.log(
    `Received ${signal}`
  );

  stoppingXray = true;

  try {
    await stopXray();
  } catch {}

  try {
    db.close();
  } catch {}

  process.exit(0);
}

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM")
);

process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);
