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
const XRAY_CONFIG =
    process.env.XRAY_CONFIG || "/app/xray/generated-config.json";

const XRAY_XHTTP_PORT =
    Number(process.env.XRAY_XHTTP_PORT || 10001);

const XRAY_WS_PORT =
    Number(process.env.XRAY_WS_PORT || 10002);

const XHTTP_PATH =
    process.env.XHTTP_PATH || "/xhttp";

const WS_PATH =
    process.env.WS_PATH || "/ws";

const VERSION = "0.7.0";

let xrayProcess = null;
let stoppingXray = false;
let xrayRestarting = false;

const sessions = new Map();

await fs.mkdir(DATA_DIR, { recursive: true });
await fs.mkdir("/app/xray", { recursive: true });

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");

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

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");
}

function randomToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function escapeHtml(value = "") {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function nowIso() {
    return new Date().toISOString();
}

function parseCookies(req) {
    const header = req.headers.cookie || "";
    const result = {};

    for (const part of header.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) continue;

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        try {
            result[key] = decodeURIComponent(value);
        } catch {
            result[key] = value;
        }
    }

    return result;
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

function requireAuth(req, res) {
    const session = getSession(req);

    if (!session) {
        redirect(res, "/login");
        return null;
    }

    return session;
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
    const body = await readBody(req);
    return new URLSearchParams(body);
}

function getPublicHost(req) {
    const forwardedHost =
        req.headers["x-forwarded-host"] ||
        process.env.RAILWAY_PUBLIC_DOMAIN ||
        req.headers.host ||
        "localhost:8080";

    return String(forwardedHost)
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
    return db.prepare(`
        SELECT *
        FROM users
        WHERE status = 'active'
          AND (
              expires_at IS NULL
              OR expires_at = ''
              OR expires_at > ?
          )
        ORDER BY id DESC
    `).all(nowIso());
}

function allUsers() {
    return db.prepare(`
        SELECT *
        FROM users
        ORDER BY id DESC
    `).all();
}

function generateXrayConfig() {
    const users = activeUsers();

    const clients = users.map(user => ({
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
            resolve();
            return;
        }

        const processToStop = xrayProcess;
        xrayProcess = null;

        const timer = setTimeout(() => {
            try {
                processToStop.kill("SIGKILL");
            } catch {}

            resolve();
        }, 3000);

        processToStop.once("exit", () => {
            clearTimeout(timer);
            resolve();
        });

        try {
            processToStop.kill("SIGTERM");
        } catch {
            clearTimeout(timer);
            resolve();
        }
    });
}

async function startXray() {
    await writeXrayConfig();

    console.log(`⚙️ Xray binary: ${XRAY_BIN}`);
    console.log(
        `⚔️ XHTTP: 127.0.0.1:${XRAY_XHTTP_PORT}${XHTTP_PATH}`
    );
    console.log(
        `🌐 WebSocket: 127.0.0.1:${XRAY_WS_PORT}${WS_PATH}`
    );

    xrayProcess = spawn(
        XRAY_BIN,
        [
            "run",
            "-config",
            XRAY_CONFIG
        ],
        {
            stdio: ["ignore", "pipe", "pipe"]
        }
    );

    xrayProcess.stdout.on("data", data => {
        process.stdout.write(`[XRAY] ${data}`);
    });

    xrayProcess.stderr.on("data", data => {
        process.stderr.write(`[XRAY] ${data}`);
    });

    xrayProcess.on("error", error => {
        console.error("❌ Xray process error:", error);
    });

    xrayProcess.on("exit", (code, signal) => {
        console.log(
            `⚠️ Xray exited. code=${code} signal=${signal}`
        );

        xrayProcess = null;

        if (!stoppingXray && !xrayRestarting) {
            setTimeout(() => {
                startXray().catch(error => {
                    console.error(
                        "❌ Xray restart failed:",
                        error
                    );
                });
            }, 1500);
        }
    });
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

function makeVlessLinks(user, origin) {
    const domain = new URL(origin).hostname;

    const xhttpParams = new URLSearchParams({
        encryption: "none",
        security: "tls",
        type: "xhttp",
        path: XHTTP_PATH,
        host: domain,
        mode: "auto"
    });

    const wsParams = new URLSearchParams({
        encryption: "none",
        security: "tls",
        type: "ws",
        path: WS_PATH,
        host: domain
    });

    return {
        xhttp:
            `vless://${user.uuid}@${domain}:443?${xhttpParams.toString()}#${encodeURIComponent(user.username)}-XHTTP`,

        websocket:
            `vless://${user.uuid}@${domain}:443?${wsParams.toString()}#${encodeURIComponent(user.username)}-WS`
    };
}

function makeSubscription(user, origin) {
    const links = makeVlessLinks(user, origin);

    return Buffer.from(
        `${links.xhttp}\n${links.websocket}`,
        "utf8"
    ).toString("base64");
}

async function qrCode(text) {
    return QRCode.toDataURL(text, {
        width: 260,
        margin: 2,
        errorCorrectionLevel: "M"
    });
}

function layout(title, body) {
    return `
<!doctype html>
<html lang="en">

<head>
<meta charset="utf-8">
<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>${escapeHtml(title)} — VergilPanel</title>

<style>

:root{
    color-scheme:dark;

    --bg:#06070b;
    --card:#0e1118;
    --card2:#151923;
    --border:#252b38;

    --text:#f5f7fb;
    --muted:#8e98a9;

    --accent:#7857ff;
    --accent2:#9a7cff;

    --green:#35d07f;
    --red:#ff596b;
}

*{
    box-sizing:border-box;
}

body{
    margin:0;
    background:
        radial-gradient(
            circle at top right,
            rgba(120,87,255,.14),
            transparent 35%
        ),
        var(--bg);

    color:var(--text);

    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

a{
    color:inherit;
    text-decoration:none;
}

.container{
    max-width:1250px;
    margin:auto;
    padding:24px;
}

.nav{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:15px;
    margin-bottom:25px;
}

.brand{
    font-size:23px;
    font-weight:900;
    letter-spacing:-.5px;
}

.brand span{
    color:var(--accent2);
}

.nav-right{
    display:flex;
    gap:10px;
    align-items:center;
}

.btn{
    display:inline-flex;
    align-items:center;
    justify-content:center;

    padding:10px 15px;

    border-radius:10px;

    border:1px solid var(--border);

    background:var(--card2);

    color:var(--text);

    cursor:pointer;

    font-size:14px;
    transition:.2s;
}

.btn:hover{
    transform:translateY(-1px);
    border-color:#454d60;
}

.btn.primary{
    background:var(--accent);
    border-color:var(--accent);
}

.btn.danger{
    background:#32131a;
    border-color:#56212b;
}

.grid{
    display:grid;
    grid-template-columns:repeat(4,1fr);
    gap:15px;
}

.card{
    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.025),
            transparent
        ),
        var(--card);

    border:1px solid var(--border);

    border-radius:17px;

    padding:20px;

    box-shadow:
        0 12px 40px rgba(0,0,0,.18);
}

.stat-label{
    color:var(--muted);
    font-size:13px;
}

.stat-value{
    font-size:30px;
    font-weight:900;
    margin-top:8px;
}

h1{
    font-size:28px;
    margin:0 0 8px;
}

h2{
    font-size:19px;
}

.muted{
    color:var(--muted);
}

.table-wrap{
    overflow:auto;
    margin-top:18px;
}

table{
    width:100%;
    border-collapse:collapse;
}

th,
td{
    padding:14px 12px;
    text-align:left;
    border-bottom:1px solid var(--border);
    white-space:nowrap;
}

th{
    color:var(--muted);
    font-size:12px;
}

.badge{
    display:inline-flex;
    padding:5px 9px;
    border-radius:999px;
    background:#202633;
    font-size:12px;
}

.badge.green{
    background:#123522;
    color:#68e9a2;
}

.badge.red{
    background:#39171c;
    color:#ff8b96;
}

.actions{
    display:flex;
    gap:8px;
}

.form{
    max-width:520px;
}

label{
    display:block;
    margin:16px 0 7px;
    color:var(--muted);
    font-size:13px;
}

input,
select{
    width:100%;
    padding:13px;

    background:#090c12;

    color:var(--text);

    border:1px solid var(--border);

    border-radius:10px;

    outline:none;
}

input:focus,
select:focus{
    border-color:var(--accent);
}

.notice{
    padding:14px;

    border-radius:12px;

    background:#141923;

    border:1px solid var(--border);

    margin-bottom:18px;
}

pre.config{
    white-space:pre-wrap;
    word-break:break-all;

    background:#080a0f;

    border:1px solid var(--border);

    padding:14px;

    border-radius:10px;

    font-size:12px;
}

.qr-grid{
    display:grid;
    grid-template-columns:repeat(2,1fr);
    gap:18px;
    margin-top:18px;
}

.qr-card{
    text-align:center;
    background:#0a0d13;
    border:1px solid var(--border);
    border-radius:15px;
    padding:18px;
}

.qr-card img{
    width:220px;
    max-width:100%;
    background:white;
    padding:8px;
    border-radius:12px;
}

.hero{
    position:relative;
    overflow:hidden;

    min-height:280px;

    border-radius:20px;

    border:1px solid var(--border);

    margin-bottom:20px;

    background:
        radial-gradient(
            circle at 80% 30%,
            rgba(120,87,255,.3),
            transparent 30%
        ),
        linear-gradient(
            110deg,
            #080a10,
            #111326
        );
}

.hero-content{
    position:relative;
    z-index:2;

    padding:35px;

    max-width:600px;
}

.hero-title{
    font-size:42px;
    font-weight:950;
    letter-spacing:-2px;
    margin-bottom:10px;
}

.hero-sub{
    color:var(--muted);
    font-size:15px;
}

.hero-sword{
    position:absolute;

    right:-30px;
    bottom:-100px;

    width:55%;
    height:320px;

    transform:rotate(-18deg);

    background:
        linear-gradient(
            90deg,
            transparent 0%,
            rgba(150,120,255,.05) 35%,
            rgba(150,120,255,.45) 50%,
            rgba(150,120,255,.04) 65%,
            transparent 100%
        );

    filter:blur(2px);
}

.status-dot{
    width:9px;
    height:9px;
    border-radius:50%;
    display:inline-block;
    background:var(--red);
    margin-right:7px;
}

.status-dot.online{
    background:var(--green);
    box-shadow:0 0 12px var(--green);
}

.login{
    min-height:100vh;
    display:grid;
    place-items:center;
    padding:20px;
}

.login .card{
    width:min(420px,100%);
}

.small{
    font-size:12px;
}

footer{
    text-align:center;
    color:var(--muted);
    padding:30px 0 10px;
}

@media(max-width:850px){

    .grid{
        grid-template-columns:repeat(2,1fr);
    }

    .qr-grid{
        grid-template-columns:1fr;
    }

    .hero-title{
        font-size:34px;
    }
}

@media(max-width:520px){

    .container{
        padding:15px;
    }

    .grid{
        grid-template-columns:1fr;
    }

    .hero-content{
        padding:25px;
    }

    .hero-sword{
        opacity:.35;
    }

    .nav{
        align-items:flex-start;
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

function loginPage(error = "") {
    return layout(
        "Login",
        `
<div class="login">

<div class="card">

<div class="brand">
⚔️ Vergil<span>Panel</span>
</div>

<p class="muted">
Sign in to your panel
</p>

${
    error
        ? `<div class="notice">${escapeHtml(error)}</div>`
        : ""
}

<form method="POST" action="/login">

<label>Username</label>

<input
    name="username"
    required
    autocomplete="username"
>

<label>Password</label>

<input
    type="password"
    name="password"
    required
    autocomplete="current-password"
>

<br><br>

<button
    class="btn primary"
    type="submit"
    style="width:100%"
>
Login
</button>

</form>

</div>

</div>
`
    );
}

function dashboardPage(req) {
    const users = allUsers();
    const active = activeUsers();

    const xrayOnline =
        Boolean(
            xrayProcess &&
            !xrayProcess.killed
        );

    return layout(
        "Dashboard",
        `
<div class="container">

<div class="nav">

<div class="brand">
⚔️ Vergil<span>Panel</span>
</div>

<div class="nav-right">

<span class="muted">
${escapeHtml(
    getSession(req)?.username || "admin"
)}
</span>

<a class="btn" href="/logout">
Logout
</a>

</div>

</div>

<div class="hero">

<div class="hero-content">

<div class="hero-title">
VERGILPANEL
</div>

<div class="hero-sub">
VLESS management powered by Xray
</div>

<br>

<span class="badge">
<span class="status-dot ${
    xrayOnline ? "online" : ""
}"></span>

Xray ${
    xrayOnline
        ? "Online"
        : "Offline"
}

</span>

</div>

<div class="hero-sword"></div>

</div>

<div class="grid">

<div class="card">

<div class="stat-label">
Users
</div>

<div class="stat-value">
${users.length}
</div>

</div>

<div class="card">

<div class="stat-label">
Active Users
</div>

<div class="stat-value">
${active.length}
</div>

</div>

<div class="card">

<div class="stat-label">
Transport
</div>

<div
    class="stat-value"
    style="font-size:20px"
>
XHTTP + WS
</div>

</div>

<div class="card">

<div class="stat-label">
Version
</div>

<div
    class="stat-value"
    style="font-size:20px"
>
v${VERSION}
</div>

</div>

</div>

<br>

<div class="card">

<div
    style="
    display:flex;
    justify-content:space-between;
    gap:15px;
    align-items:center
    "
>

<div>

<h2>
Users
</h2>

<div class="muted">
Automatic Xray configuration
</div>

</div>

<a
    class="btn primary"
    href="/users/new"
>
＋ New User
</a>

</div>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>
Username
</th>

<th>
Protocol
</th>

<th>
UUID
</th>

<th>
Status
</th>

<th>
Configs
</th>

<th>
Actions
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
<span class="badge">
VLESS
</span>
</td>

<td class="small">
${escapeHtml(user.uuid)}
</td>

<td>

${
    user.status === "active"
        ? `
<span class="badge green">
Active
</span>
`
        : `
<span class="badge red">
Disabled
</span>
`
}

</td>

<td>

<a
    class="btn"
    href="/users/config?id=${user.id}"
>
Config
</a>

</td>

<td>

<div class="actions">

<form
    method="POST"
    action="/users/toggle"
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

${
    user.status === "active"
        ? "Disable"
        : "Enable"
}

</button>

</form>

<form
    method="POST"
    action="/users/delete"
    onsubmit="return confirm('Delete this user?')"
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
Delete
</button>

</form>

</div>

</td>

</tr>

`).join("")
        : `
<tr>

<td
    colspan="6"
    class="muted"
>
No users yet.
</td>

</tr>
`
}

</tbody>

</table>

</div>

</div>

<footer>
VergilPanel v${VERSION} · Xray automatic management
</footer>

</div>
`
    );
}

function newUserPage(error = "") {
    return layout(
        "New User",
        `
<div class="container">

<div class="nav">

<div class="brand">
⚔️ Vergil<span>Panel</span>
</div>

<a
    class="btn"
    href="/dashboard"
>
← Dashboard
</a>

</div>

<div class="card form">

<h1>
New User
</h1>

<p class="muted">
UUID and subscription token are generated automatically.
</p>

${
    error
        ? `<div class="notice">${escapeHtml(error)}</div>`
        : ""
}

<form
    method="POST"
    action="/users/new"
>

<label>
Username
</label>

<input
    name="username"
    required
    maxlength="64"
    placeholder="Vexa"
>

<label>
Traffic Limit
</label>

<select name="traffic_limit">

<option value="0">
Unlimited
</option>

<option value="10737418240">
10 GB
</option>

<option value="53687091200">
50 GB
</option>

<option value="107374182400">
100 GB
</option>

<option value="536870912000">
500 GB
</option>

</select>

<label>
Expiry
</label>

<input
    type="datetime-local"
    name="expires_at"
>

<br><br>

<button
    class="btn primary"
    type="submit"
>
Create User
</button>

</form>

</div>

</div>
`
    );
}

async function configPage(req, user) {
    const origin = getPublicOrigin(req);

    const links = makeVlessLinks(
        user,
        origin
    );

    const subscriptionUrl =
        `${origin}/sub/${user.subscription_token}`;

    const xhttpQr =
        await qrCode(links.xhttp);

    const wsQr =
        await qrCode(links.websocket);

    const subQr =
        await qrCode(subscriptionUrl);

    return layout(
        `${user.username} Config`,
        `
<div class="container">

<div class="nav">

<div class="brand">
⚔️ Vergil<span>Panel</span>
</div>

<a
    class="btn"
    href="/dashboard"
>
← Dashboard
</a>

</div>

<div class="card">

<h1>
${escapeHtml(user.username)}
</h1>

<p class="muted">
VLESS · automatic configuration
</p>

<div class="notice">

<strong>
Subscription URL
</strong>

<pre class="config">${escapeHtml(subscriptionUrl)}</pre>

<button
    class="btn primary"
    onclick='copyText(${JSON.stringify(subscriptionUrl)})'
>
Copy Subscription
</button>

</div>

<div class="qr-grid">

<div class="qr-card">

<h3>
Subscription QR
</h3>

<img
    src="${subQr}"
    alt="Subscription QR"
>

<br><br>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(subscriptionUrl)})'
>
Copy
</button>

</div>

<div class="qr-card">

<h3>
XHTTP QR
</h3>

<img
    src="${xhttpQr}"
    alt="XHTTP QR"
>

<br><br>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(links.xhttp)})'
>
Copy
</button>

</div>

</div>

<h2>
🚀 VLESS + XHTTP
</h2>

<pre class="config">${escapeHtml(links.xhttp)}</pre>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(links.xhttp)})'
>
Copy XHTTP
</button>

<br><br>

<h2>
🌐 VLESS + WebSocket
</h2>

<pre class="config">${escapeHtml(links.websocket)}</pre>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(links.websocket)})'
>
Copy WebSocket
</button>

<div class="qr-grid">

<div class="qr-card">

<h3>
XHTTP
</h3>

<img
    src="${xhttpQr}"
    alt="XHTTP QR"
>

</div>

<div class="qr-card">

<h3>
WebSocket
</h3>

<img
    src="${wsQr}"
    alt="WebSocket QR"
>

</div>

</div>

<h2>
UUID
</h2>

<pre class="config">${escapeHtml(user.uuid)}</pre>

<p class="muted small">
Public HTTPS is provided by Railway.
Xray itself terminates no TLS on the internal ports.
</p>

</div>

</div>

<script>

async function copyText(text){

    try{

        await navigator.clipboard.writeText(text);

        alert("Copied!");

    }catch{

        prompt(
            "Copy this:",
            text
        );

    }

}

</script>
`
    );
}

function setupComplete() {
    return (
        db
            .prepare(
                "SELECT COUNT(*) AS count FROM admins"
            )
            .get()
            .count > 0
    );
}

function ensureDefaultAdmin() {
    const username =
        String(
            process.env.ADMIN_USERNAME || ""
        ).trim();

    const password =
        String(
            process.env.ADMIN_PASSWORD || ""
        );

    if (!username || !password) {
        return;
    }

    const existing = db.prepare(`
        SELECT id
        FROM admins
        WHERE username = ?
    `).get(username);

    if (existing) {

        db.prepare(`
            UPDATE admins
            SET password_hash = ?
            WHERE id = ?
        `).run(
            hashPassword(password),
            existing.id
        );

        console.log(
            `👤 Admin environment password synchronized: ${username}`
        );

        return;
    }

    db.prepare(`
        INSERT INTO admins(
            username,
            password_hash,
            created_at
        )
        VALUES (?, ?, ?)
    `).run(
        username,
        hashPassword(password),
        nowIso()
    );

    console.log(
        `👤 Default admin created: ${username}`
    );
}

function authenticate(username, password) {
    const admin = db.prepare(`
        SELECT *
        FROM admins
        WHERE username = ?
    `).get(username);

    if (!admin) {
        return false;
    }

    return (
        admin.password_hash ===
        hashPassword(password)
    );
}

async function createUser(form) {

    const username =
        String(
            form.get("username") || ""
        ).trim();

    if (!username) {
        throw new Error(
            "Username is required."
        );
    }

    const exists = db.prepare(`
        SELECT id
        FROM users
        WHERE username = ?
    `).get(username);

    if (exists) {
        throw new Error(
            "Username already exists."
        );
    }

    const uuid =
        crypto.randomUUID();

    const subscriptionToken =
        randomToken(32);

    const trafficLimit =
        Number(
            form.get("traffic_limit") || 0
        );

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
                "Invalid expiry date."
            );
        }

        expiresAt =
            date.toISOString();
    }

    const result =
        db.prepare(`
            INSERT INTO users(
                username,
                uuid,
                protocol,
                traffic_limit_bytes,
                traffic_used_bytes,
                expires_at,
                status,
                subscription_token,
                created_at
            )
            VALUES (
                ?,
                ?,
                'vless',
                ?,
                0,
                ?,
                'active',
                ?,
                ?
            )
        `).run(
            username,
            uuid,
            Number.isFinite(
                trafficLimit
            )
                ? trafficLimit
                : 0,
            expiresAt,
            subscriptionToken,
            nowIso()
        );

    await restartXray();

    return db.prepare(`
        SELECT *
        FROM users
        WHERE id = ?
    `).get(
        result.lastInsertRowid
    );
}

async function deleteUser(id) {

    db.prepare(`
        DELETE FROM users
        WHERE id = ?
    `).run(
        Number(id)
    );

    await restartXray();
}

async function toggleUser(id) {

    const user =
        db.prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `).get(
            Number(id)
        );

    if (!user) {
        throw new Error(
            "User not found."
        );
    }

    const newStatus =
        user.status === "active"
            ? "disabled"
            : "active";

    db.prepare(`
        UPDATE users
        SET status = ?
        WHERE id = ?
    `).run(
        newStatus,
        Number(id)
    );

    await restartXray();
}

function proxyHttpToXray(
    req,
    res,
    targetPort
) {

    const options = {
        hostname: "127.0.0.1",
        port: targetPort,
        path: req.url,
        method: req.method,

        headers: {
            ...req.headers,
            host:
                `127.0.0.1:${targetPort}`
        }
    };

    const proxy =
        http.request(
            options,
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

function proxyWebSocket(
    req,
    clientSocket,
    head
) {

    const upstream =
        net.connect({
            host: "127.0.0.1",
            port: XRAY_WS_PORT
        });

    upstream.on(
        "connect",
        () => {

            const headers = [];

            headers.push(
                `${req.method} ${req.url} HTTP/${req.httpVersion}`
            );

            for (
                const [key, value]
                of Object.entries(req.headers)
            ) {

                if (
                    Array.isArray(value)
                ) {

                    for (
                        const item
                        of value
                    ) {

                        headers.push(
                            `${key}: ${item}`
                        );
                    }

                } else {

                    headers.push(
                        `${key}: ${value}`
                    );
                }
            }

            headers.push("");
            headers.push("");

            upstream.write(
                headers.join("\r\n")
            );

            if (
                head &&
                head.length
            ) {
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

async function subscriptionResponse(
    req,
    res,
    token
) {

    const user =
        db.prepare(`
            SELECT *
            FROM users
            WHERE subscription_token = ?
        `).get(token);

    if (!user) {

        sendJson(
            res,
            {
                ok: false,
                error:
                    "Subscription not found."
            },
            404
        );

        return;
    }

    if (
        user.status !== "active"
    ) {

        sendJson(
            res,
            {
                ok: false,
                error:
                    "Subscription disabled."
            },
            403
        );

        return;
    }

    const origin =
        getPublicOrigin(req);

    const content =
        makeSubscription(
            user,
            origin
        );

    res.writeHead(
        200,
        {
            "Content-Type":
                "text/plain; charset=utf-8",

            "Cache-Control":
                "no-store",

            "Profile-Update-Interval":
                "24"
        }
    );

    res.end(content);
}

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

        const pathname =
            url.pathname;

        /*
         * XHTTP
         */

        if (
            pathname === XHTTP_PATH ||
            pathname.startsWith(
                `${XHTTP_PATH}/`
            )
        ) {

            proxyHttpToXray(
                req,
                res,
                XRAY_XHTTP_PORT
            );

            return;
        }

        /*
         * Subscription
         */

        if (
            pathname.startsWith("/sub/")
        ) {

            const token =
                pathname.slice(
                    "/sub/".length
                );

            await subscriptionResponse(
                req,
                res,
                token
            );

            return;
        }

        /*
         * Health
         */

        if (
            pathname === "/health"
        ) {

            sendJson(
                res,
                {
                    ok: true,
                    panel: VERSION,
                    xray:
                        Boolean(
                            xrayProcess &&
                            !xrayProcess.killed
                        ),
                    transports: [
                        "xhttp",
                        "websocket"
                    ]
                }
            );

            return;
        }

        /*
         * Login
         */

        if (
            pathname === "/login" &&
            req.method === "GET"
        ) {

            if (
                getSession(req)
            ) {

                redirect(
                    res,
                    "/dashboard"
                );

                return;
            }

            sendHtml(
                res,
                loginPage()
            );

            return;
        }

        if (
            pathname === "/login" &&
            req.method === "POST"
        ) {

            const form =
                await readForm(req);

            const username =
                String(
                    form.get(
                        "username"
                    ) || ""
                ).trim();

            const password =
                String(
                    form.get(
                        "password"
                    ) || ""
                );

            if (
                !authenticate(
                    username,
                    password
                )
            ) {

                sendHtml(
                    res,
                    loginPage(
                        "Invalid username or password."
                    ),
                    401
                );

                return;
            }

            const token =
                randomToken(32);

            sessions.set(
                token,
                {
                    username,
                    createdAt:
                        Date.now()
                }
            );

            res.writeHead(
                302,
                {
                    Location:
                        "/dashboard",

                    "Set-Cookie":
                        `vergil_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Secure`
                }
            );

            res.end();

            return;
        }

        /*
         * Setup
         */

        if (
            pathname === "/setup" &&
            req.method === "GET"
        ) {

            if (
                setupComplete()
            ) {

                redirect(
                    res,
                    "/login"
                );

                return;
            }

            sendHtml(
                res,
                `
                ${layout(
                    "Setup",
                    `
                    <div class="login">
                    <div class="card">

                    <div class="brand">
                    ⚔️ Vergil<span>Panel</span>
                    </div>

                    <h2>
                    Initial Setup
                    </h2>

                    <p class="muted">
                    Create the first administrator account.
                    </p>

                    <form
                        method="POST"
                        action="/setup"
                    >

                    <label>
                    Username
                    </label>

                    <input
                        name="username"
                        required
                        value="admin"
                    >

                    <label>
                    Password
                    </label>

                    <input
                        type="password"
                        name="password"
                        required
                        minlength="6"
                    >

                    <label>
                    Confirm Password
                    </label>

                    <input
                        type="password"
                        name="confirm"
                        required
                        minlength="6"
                    >

                    <br><br>

                    <button
                        class="btn primary"
                        type="submit"
                        style="width:100%"
                    >
                    Create Panel
                    </button>

                    </form>

                    </div>
                    </div>
                    `
                )}
                `
            );

            return;
        }

        if (
            pathname === "/setup" &&
            req.method === "POST"
        ) {

            if (
                setupComplete()
            ) {

                redirect(
                    res,
                    "/login"
                );

                return;
            }

            const form =
                await readForm(req);

            const username =
                String(
                    form.get(
                        "username"
                    ) || ""
                ).trim();

            const password =
                String(
                    form.get(
                        "password"
                    ) || ""
                );

            const confirm =
                String(
                    form.get(
                        "confirm"
                    ) || ""
                );

            if (
                !username ||
                !password
            ) {

                sendHtml(
                    res,
                    loginPage(
                        "Username and password are required."
                    ),
                    400
                );

                return;
            }

            if (
                password.length < 6
            ) {

                sendHtml(
                    res,
                    loginPage(
                        "Password must contain at least 6 characters."
                    ),
                    400
                );

                return;
            }

            if (
                password !== confirm
            ) {

                sendHtml(
                    res,
                    loginPage(
                        "Passwords do not match."
                    ),
                    400
                );

                return;
            }

            db.prepare(`
                INSERT INTO admins(
                    username,
                    password_hash,
                    created_at
                )
                VALUES (?, ?, ?)
            `).run(
                username,
                hashPassword(password),
                nowIso()
            );

            redirect(
                res,
                "/login"
            );

            return;
        }

        /*
         * Logout
         */

        if (
            pathname === "/logout"
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

            res.end();

            return;
        }

        /*
         * Authentication
         */

        const session =
            requireAuth(
                req,
                res
            );

        if (!session) {
            return;
        }

        /*
         * Dashboard
         */

        if (
            pathname === "/" ||
            pathname === "/dashboard"
        ) {

            sendHtml(
                res,
                dashboardPage(req)
            );

            return;
        }

        /*
         * New User
         */

        if (
            pathname === "/users/new" &&
            req.method === "GET"
        ) {

            sendHtml(
                res,
                newUserPage()
            );

            return;
        }

        if (
            pathname === "/users/new" &&
            req.method === "POST"
        ) {

            try {

                const form =
                    await readForm(req);

                const user =
                    await createUser(
                        form
                    );

                console.log(
                    `👤 User created: ${user.username} (${user.uuid})`
                );

                redirect(
                    res,
                    `/users/config?id=${user.id}`
                );

            } catch (error) {

                console.error(
                    "User creation failed:",
                    error
                );

                sendHtml(
                    res,
                    newUserPage(
                        error?.message ||
                        "Failed to create user."
                    ),
                    500
                );
            }

            return;
        }

        /*
         * User Config
         */

        if (
            pathname === "/users/config" &&
            req.method === "GET"
        ) {

            const id =
                Number(
                    url.searchParams.get(
                        "id"
                    )
                );

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE id = ?
                `).get(id);

            if (!user) {

                sendHtml(
                    res,
                    layout(
                        "Not Found",
                        `
                        <div class="container">
                        <div class="card">
                        <h1>User not found</h1>
                        <a class="btn" href="/dashboard">
                        Dashboard
                        </a>
                        </div>
                        </div>
                        `
                    ),
                    404
                );

                return;
            }

            sendHtml(
                res,
                await configPage(
                    req,
                    user
                )
            );

            return;
        }

        /*
         * Toggle User
         */

        if (
            pathname === "/users/toggle" &&
            req.method === "POST"
        ) {

            const form =
                await readForm(req);

            try {

                await toggleUser(
                    form.get("id")
                );

            } catch (error) {

                console.error(
                    "Toggle user failed:",
                    error
                );
            }

            redirect(
                res,
                "/dashboard"
            );

            return;
        }

        /*
         * Delete User
         */

        if (
            pathname === "/users/delete" &&
            req.method === "POST"
        ) {

            const form =
                await readForm(req);

            try {

                await deleteUser(
                    form.get("id")
                );

            } catch (error) {

                console.error(
                    "Delete user failed:",
                    error
                );
            }

            redirect(
                res,
                "/dashboard"
            );

            return;
        }

        sendHtml(
            res,
            layout(
                "404",
                `
                <div class="container">
                <div class="card">
                <h1>404</h1>
                <p class="muted">
                Not Found
                </p>
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

        if (
            !res.headersSent
        ) {

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

const server =
    http.createServer(
        handleRequest
    );

/*
 * WebSocket Upgrade
 */

server.on(
    "upgrade",
    (req, socket, head) => {

        try {

            const url =
                new URL(
                    req.url,
                    `http://${req.headers.host || "localhost"}`
                );

            if (
                url.pathname === WS_PATH ||
                url.pathname.startsWith(
                    `${WS_PATH}/`
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

ensureDefaultAdmin();

await startXray();

server.listen(
    PORT,
    HOST,
    () => {

        console.log(
            `⚔️ VergilPanel v${VERSION} running on ${HOST}:${PORT}`
        );

        console.log(
            `📦 Database: ${DB_PATH}`
        );

        console.log(
            `🌐 Public domain: ${
                process.env.RAILWAY_PUBLIC_DOMAIN ||
                "detected from request"
            }`
        );

        console.log(
            `🚀 XHTTP path: ${XHTTP_PATH}`
        );

        console.log(
            `🌐 WebSocket path: ${WS_PATH}`
        );

        console.log(
            `⚔️ Railway TCP Proxy is NOT required`
        );
    }
);

async function shutdown(signal) {

    console.log(
        `\nReceived ${signal}`
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
