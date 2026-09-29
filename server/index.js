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

const XRAY_BIN =
    process.env.XRAY_BIN || "/opt/xray/xray";

const XRAY_CONFIG =
    process.env.XRAY_CONFIG ||
    "/app/xray/generated-config.json";

const XRAY_XHTTP_PORT =
    Number(process.env.XRAY_XHTTP_PORT || 10001);

const XRAY_WS_PORT =
    Number(process.env.XRAY_WS_PORT || 10002);

const XHTTP_PATH =
    process.env.XHTTP_PATH || "/xhttp";

const WS_PATH =
    process.env.WS_PATH || "/ws";

const VERSION = "0.8.0";

let xrayProcess = null;
let stoppingXray = false;
let xrayRestarting = false;
let xrayRestartTimer = null;
let xrayRestartAttempts = 0;

const proxyHttpAgent = new http.Agent({ keepAlive: true });

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

async function checkTcpPort(port, timeout = 1200) {
    return new Promise(resolve => {
        let settled = false;
        const socket = net.createConnection({
            host: "127.0.0.1",
            port
        });

        const finish = isOpen => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve(isOpen);
        };

        socket.setTimeout(timeout);
        socket.once("connect", () => finish(true));
        socket.once("timeout", () => finish(false));
        socket.once("error", () => finish(false));
    });
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
    return new URLSearchParams(
        await readBody(req)
    );
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
    const forwarded =
        req.headers["x-forwarded-host"];

    const host =
        forwarded ||
        process.env.RAILWAY_PUBLIC_DOMAIN ||
        req.headers.host ||
        "localhost:8080";

    return String(host)
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

function getAdmin() {
    return db.prepare(`
        SELECT *
        FROM admins
        ORDER BY id ASC
        LIMIT 1
    `).get();
}

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
        `âš™ï¸ Xray config synced: ${activeUsers().length} active user(s)`
    );
}

function clearXrayRestartTimer() {
    if (xrayRestartTimer) {
        clearTimeout(xrayRestartTimer);
        xrayRestartTimer = null;
    }
}

function scheduleXrayRestart() {
    if (stoppingXray || xrayRestarting || xrayRestartTimer) return;

    xrayRestartAttempts = Math.min(xrayRestartAttempts + 1, 8);
    const delay = Math.min(1500 * (2 ** (xrayRestartAttempts - 1)), 30000);

    console.warn(`âš ï¸ Scheduling Xray restart in ${delay}ms (attempt ${xrayRestartAttempts})`);
    xrayRestartTimer = setTimeout(async () => {
        xrayRestartTimer = null;

        if (stoppingXray || xrayRestarting) return;

        try {
            await startXray();
        } catch (error) {
            console.error("âŒ Xray restart failed:", error);
            scheduleXrayRestart();
        }
    }, delay);
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

    console.log(`âš™ï¸ Xray binary: ${XRAY_BIN}`);

    const child = spawn(
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
    xrayProcess = child;

    child.stdout.on("data", data => {
        process.stdout.write(`[XRAY] ${data}`);
    });

    child.stderr.on("data", data => {
        process.stderr.write(`[XRAY] ${data}`);
    });

    child.on("error", error => {
        console.error("âŒ Xray process error:", error);

        if (xrayProcess === child) {
            xrayProcess = null;
        }

        if (!stoppingXray && !xrayRestarting) {
            scheduleXrayRestart();
        }
    });

    child.on("exit", (code, signal) => {
        console.log(`âš ï¸ Xray exited. code=${code} signal=${signal}`);

        if (xrayProcess === child) {
            xrayProcess = null;
        }

        if (!stoppingXray && !xrayRestarting) {
            scheduleXrayRestart();
        }
    });
}

async function restartXray() {
    if (xrayRestarting) return;

    xrayRestarting = true;
    clearXrayRestartTimer();
    let restartFailed = false;

    try {
        await stopXray();
        await startXray();
    } catch (error) {
        console.error("âŒ Xray restart failed:", error);
        restartFailed = true;
    } finally {
        xrayRestarting = false;
    }

    if (restartFailed) scheduleXrayRestart();
}

function makeVlessLinks(user, origin) {
    const domain =
        new URL(origin).hostname;

    const xhttpParams =
        new URLSearchParams({
            encryption: "none",
            security: "tls",
            type: "xhttp",
            path: XHTTP_PATH,
            host: domain,
            mode: "auto"
        });

    const wsParams =
        new URLSearchParams({
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

/*
 * Dummy configuration
 *
 * Ø§ÛŒÙ† Ú©Ø§Ù†ÙÛŒÚ¯ Ø¹Ù…Ø¯Ø§Ù‹ Ú©Ø§Ø± Ù†Ù…ÛŒâ€ŒÚ©Ù†Ø¯.
 * ÙÙ‚Ø· Ø¨Ø±Ø§ÛŒ Ù†Ù…Ø§ÛŒØ´ Ù¾ÛŒØ§Ù… Ù…Ø§Ù„Ú©/Ø¨Ø±Ù†Ø¯ Ø¯Ø§Ø®Ù„ Subscription Ø§Ø³Øª.
 */

function makeDummyConfig() {
    const params =
        new URLSearchParams({
            encryption: "none",
            security: "none",
            type: "tcp"
        });

    return (
        `vless://00000000-0000-0000-0000-000000000000@0.0.0.0:443?${params.toString()}#${encodeURIComponent(
            "Ø³Ø§Ø®ØªÙ‡ Ø´Ø¯Ù‡ ØªÙˆØ³Ø· ÛŒØ§Ø³ÛŒÙ† - Ú©Ø§Ù…Ù„Ø§ Ø±Ø§ÛŒÚ¯Ø§Ù† Ùˆ ØºÛŒØ±Ù‚Ø§Ø¨Ù„ ÙØ±ÙˆØ´"
        )}`
    );
}

function makeSubscription(user, origin) {
    const links =
        makeVlessLinks(
            user,
            origin
        );

    const dummy =
        makeDummyConfig();

    return Buffer.from(
        [
            links.xhttp,
            links.websocket,
            dummy
        ].join("\n"),
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

<html lang="fa" dir="rtl">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>

<title>
${escapeHtml(title)} â€” VergilPanel
</title>

<style>

:root{
    --bg:#03070d;
    --bg2:#07111d;
    --card:rgba(10,22,36,.78);
    --card2:rgba(12,30,48,.9);
    --border:rgba(100,210,255,.16);

    --text:#eefaff;
    --muted:#7895a8;

    --blue:#38cfff;
    --cyan:#79e7ff;
    --deep:#075b83;

    --green:#38e39a;
    --red:#ff5d73;

    --shadow:
        0 20px 70px rgba(0,0,0,.45);
}

*{
    box-sizing:border-box;
}

html{
    scroll-behavior:smooth;
}

body{
    margin:0;

    color:var(--text);

    font-family:
        Vazirmatn,
        Tahoma,
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at 80% 5%,
            rgba(35,198,255,.16),
            transparent 28%
        ),
        radial-gradient(
            circle at 10% 90%,
            rgba(0,94,145,.16),
            transparent 30%
        ),
        linear-gradient(
            135deg,
            #02050a,
            #06111d 50%,
            #02070d
        );

    min-height:100vh;
}

body::before{
    content:"";

    position:fixed;

    inset:0;

    pointer-events:none;

    background:
        linear-gradient(
            120deg,
            transparent 30%,
            rgba(92,221,255,.025),
            transparent 70%
        );

    z-index:-1;
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
    display:flex;
    align-items:center;
    gap:10px;

    font-size:23px;
    font-weight:1000;

    letter-spacing:-1px;
}

.brand-icon{
    width:39px;
    height:39px;

    display:grid;
    place-items:center;

    border-radius:12px;

    background:
        linear-gradient(
            145deg,
            rgba(111,227,255,.22),
            rgba(0,92,145,.18)
        );

    border:1px solid
        rgba(94,218,255,.25);

    box-shadow:
        0 0 30px
        rgba(39,201,255,.15);
}

.brand span{
    color:var(--cyan);

    text-shadow:
        0 0 25px
        rgba(64,210,255,.45);
}

.nav-right{
    display:flex;
    align-items:center;
    gap:9px;
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

    transition:
        .2s ease;

    box-shadow:
        inset 0 1px
        rgba(255,255,255,.03);
}

.btn:hover{
    transform:translateY(-2px);

    border-color:
        rgba(91,221,255,.45);

    box-shadow:
        0 8px 25px
        rgba(0,150,210,.12);
}

.btn.primary{
    color:#001018;

    background:
        linear-gradient(
            135deg,
            var(--cyan),
            var(--blue)
        );

    border-color:var(--blue);

    font-weight:900;

    box-shadow:
        0 0 25px
        rgba(54,207,255,.2);
}

.btn.danger{
    background:
        rgba(91,18,32,.45);

    border-color:
        rgba(255,75,100,.25);

    color:#ff9aa8;
}

.grid{
    display:grid;

    grid-template-columns:
        repeat(4,1fr);

    gap:15px;
}

.card{
    background:
        linear-gradient(
            145deg,
            rgba(27,68,94,.15),
            rgba(5,13,22,.82)
        );

    border:1px solid var(--border);

    border-radius:19px;

    padding:20px;

    box-shadow:var(--shadow);

    backdrop-filter:
        blur(16px);
}

.stat-label{
    color:var(--muted);
    font-size:12px;
}

.stat-value{
    font-size:30px;
    font-weight:1000;
    margin-top:7px;

    direction:ltr;
    text-align:right;
}

.hero{
    position:relative;

    min-height:350px;

    overflow:hidden;

    border-radius:25px;

    border:1px solid
        rgba(94,218,255,.2);

    margin-bottom:20px;

    background:
        radial-gradient(
            circle at 80% 55%,
            rgba(47,210,255,.22),
            transparent 23%
        ),
        linear-gradient(
            110deg,
            #02060b,
            #071522 55%,
            #02070d
        );

    box-shadow:
        0 30px 100px
        rgba(0,0,0,.5),
        inset 0 0 100px
        rgba(45,195,255,.04);
}

.hero::after{
    content:"";

    position:absolute;

    right:-10%;
    bottom:-65%;

    width:70%;
    height:120%;

    background:
        radial-gradient(
            ellipse,
            rgba(61,220,255,.24),
            transparent 62%
        );

    filter:blur(25px);

    transform:
        rotate(-15deg);

    pointer-events:none;
}

.hero-content{
    position:relative;

    z-index:3;

    padding:46px;

    max-width:650px;

    text-align:right;
}

.hero-kicker{
    color:var(--cyan);

    font-size:12px;

    letter-spacing:4px;

    font-weight:900;

    margin-bottom:12px;

    direction:ltr;
    text-align:right;
}

.hero-title{
    direction:ltr;
    text-align:left;

    font-size:
        clamp(42px,7vw,75px);

    line-height:.95;

    font-weight:1000;

    letter-spacing:-5px;

    background:
        linear-gradient(
            120deg,
            #ffffff,
            #8eeeff 50%,
            #28bce9
        );

    -webkit-background-clip:text;
    background-clip:text;

    color:transparent;

    filter:
        drop-shadow(
            0 0 25px
            rgba(58,210,255,.25)
        );
}

.hero-sub{
    margin-top:18px;

    color:#a5c0ce;

    font-size:15px;

    max-width:500px;
}

.powered{
    margin-top:20px;

    font-size:11px;

    letter-spacing:3px;

    color:
        rgba(136,226,255,.7);

    direction:ltr;
    text-align:left;
}

.flame{
    position:absolute;

    right:2%;
    bottom:-20%;

    width:54%;
    height:125%;

    opacity:.8;

    transform:
        rotate(-18deg);

    background:
        radial-gradient(
            ellipse at 50% 75%,
            rgba(42,218,255,.55),
            rgba(13,124,177,.22) 32%,
            transparent 67%
        );

    filter:
        blur(9px);

    mix-blend-mode:
        screen;
}

.sword{
    position:absolute;

    right:15%;
    top:-10%;

    width:5px;
    height:125%;

    transform:
        rotate(22deg);

    background:
        linear-gradient(
            180deg,
            transparent,
            #d8faff 25%,
            #4edaff 55%,
            transparent
        );

    box-shadow:
        0 0 30px
        rgba(63,218,255,.75);

    opacity:.7;
}

.status{
    display:inline-flex;

    align-items:center;

    padding:7px 11px;

    border-radius:999px;

    background:
        rgba(11,30,43,.8);

    border:1px solid
        rgba(85,220,255,.14);

    font-size:12px;

    margin-top:20px;
}

.status-dot{
    width:8px;
    height:8px;

    border-radius:50%;

    background:var(--red);

    margin-left:7px;
}

.status-dot.online{
    background:var(--green);

    box-shadow:
        0 0 14px
        var(--green);
}

.table-wrap{
    overflow:auto;

    margin-top:18px;
}

table{
    width:100%;

    border-collapse:
        collapse;
}

th,
td{
    padding:14px 12px;

    text-align:right;

    border-bottom:
        1px solid
        rgba(120,190,220,.09);

    white-space:nowrap;
}

th{
    color:var(--muted);

    font-size:11px;
}

.badge{
    display:inline-flex;

    align-items:center;

    padding:5px 9px;

    border-radius:999px;

    background:
        rgba(110,150,175,.09);

    border:1px solid
        rgba(130,190,215,.08);

    font-size:11px;
}

.badge.green{
    color:#6ff0ae;

    background:
        rgba(26,100,68,.2);

    border-color:
        rgba(64,221,142,.14);
}

.badge.red{
    color:#ff8999;

    background:
        rgba(112,24,40,.2);
}

.actions{
    display:flex;
    gap:7px;
}

h1{
    margin:0 0 8px;

    font-size:28px;
}

h2{
    font-size:19px;
}

h3{
    font-size:15px;
}

.muted{
    color:var(--muted);
}

.small{
    font-size:11px;
}

.form{
    max-width:600px;
    margin:auto;
}

label{
    display:block;

    margin:
        17px 0 7px;

    color:#9ab7c7;

    font-size:12px;
}

input,
select{
    width:100%;

    padding:13px 14px;

    background:
        rgba(2,9,15,.75);

    color:var(--text);

    border:
        1px solid
        rgba(100,200,235,.13);

    border-radius:11px;

    outline:none;

    font-family:inherit;
}

input:focus,
select:focus{
    border-color:
        rgba(65,211,255,.55);

    box-shadow:
        0 0 0 3px
        rgba(50,200,255,.07);
}

.notice{
    padding:15px;

    border-radius:13px;

    background:
        rgba(18,49,67,.35);

    border:
        1px solid
        rgba(73,208,255,.13);

    margin:
        15px 0;
}

pre.config{
    white-space:pre-wrap;

    word-break:break-all;

    direction:ltr;

    text-align:left;

    background:
        rgba(1,7,12,.8);

    border:
        1px solid
        rgba(94,218,255,.1);

    padding:14px;

    border-radius:11px;

    font-size:11px;

    line-height:1.7;
}

.qr-grid{
    display:grid;

    grid-template-columns:
        repeat(2,1fr);

    gap:18px;

    margin-top:18px;
}

.qr-card{
    text-align:center;

    background:
        rgba(3,12,20,.72);

    border:
        1px solid
        rgba(90,210,245,.1);

    border-radius:17px;

    padding:18px;
}

.qr-card img{
    width:220px;

    max-width:100%;

    background:#fff;

    padding:8px;

    border-radius:12px;
}

.settings-icon{
    font-size:40px;

    margin-bottom:10px;
}

.login{
    min-height:100vh;

    display:grid;

    place-items:center;

    padding:20px;
}

.login-card{
    width:min(440px,100%);

    position:relative;

    overflow:hidden;
}

.login-card::before{
    content:"";

    position:absolute;

    width:250px;
    height:250px;

    right:-100px;
    top:-120px;

    background:
        radial-gradient(
            circle,
            rgba(43,211,255,.25),
            transparent 65%
        );

    pointer-events:none;
}

.login-logo{
    text-align:center;

    font-size:34px;

    font-weight:1000;

    direction:ltr;
}

.login-logo span{
    color:var(--cyan);
}

.login-sub{
    text-align:center;

    color:var(--muted);

    margin-bottom:25px;

    font-size:12px;
}

.section-title{
    display:flex;

    justify-content:space-between;

    align-items:center;

    gap:10px;
}

.footer{
    text-align:center;

    color:
        rgba(115,160,180,.55);

    padding:35px 0 10px;

    font-size:10px;

    letter-spacing:2px;

    direction:ltr;
}

@media(max-width:850px){

    .grid{
        grid-template-columns:
            repeat(2,1fr);
    }

    .qr-grid{
        grid-template-columns:1fr;
    }

    .hero-content{
        padding:35px;
    }

    .flame{
        opacity:.35;
        width:80%;
    }

}

@media(max-width:550px){

    .container{
        padding:14px;
    }

    .grid{
        grid-template-columns:1fr;
    }

    .nav{
        align-items:flex-start;
    }

    .nav-right{
        flex-wrap:wrap;
        justify-content:flex-end;
    }

    .hero{
        min-height:330px;
    }

    .hero-title{
        font-size:43px;
    }

    .hero-content{
        padding:27px;
    }

    .hero-sub{
        font-size:13px;
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

<div class="card login-card">

<div class="login-logo">
âš”ï¸ VERGIL<span>PANEL</span>
</div>

<div class="login-sub">
X R A Y   M A N A G E M E N T   S Y S T E M
</div>

${
    error
        ? `
<div class="notice">
${escapeHtml(error)}
</div>
`
        : ""
}

<form
    method="POST"
    action="/login"
>

<label>
Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ
</label>

<input
    name="username"
    required
    autocomplete="username"
    dir="ltr"
>

<label>
Ø±Ù…Ø² Ø¹Ø¨ÙˆØ±
</label>

<input
    type="password"
    name="password"
    required
    autocomplete="current-password"
    dir="ltr"
>

<br>

<button
    class="btn primary"
    type="submit"
    style="width:100%"
>
ÙˆØ±ÙˆØ¯ Ø¨Ù‡ Ù¾Ù†Ù„
</button>

</form>

<div class="footer">
POWERED BY YASIN BEHZAD
</div>

</div>

</div>
`
    );
}

function dashboardPage(req) {
    const users = allUsers();
    const active = activeUsers();

    const online =
        Boolean(
            xrayProcess &&
            !xrayProcess.killed
        );

    const admin =
        getAdmin();

    return layout(
        "Dashboard",
        `
<div class="container">

<div class="nav">

<a
    href="/dashboard"
    class="brand"
>

<div class="brand-icon">
âš”ï¸
</div>

<div>
VERGIL<span>PANEL</span>
</div>

</a>

<div class="nav-right">

<span class="muted small">
${escapeHtml(
    admin?.username || "admin"
)}
</span>

<a
    class="btn"
    href="/settings"
>
âš™ï¸ ØªÙ†Ø¸ÛŒÙ…Ø§Øª
</a>

<a
    class="btn danger"
    href="/logout"
>
Ø®Ø±ÙˆØ¬
</a>

</div>

</div>

<div class="hero">

<div class="hero-content">

<div class="hero-kicker">
XRAY MANAGEMENT SYSTEM
</div>

<div class="hero-title">
VERGIL
</div>

<div class="hero-sub">
Ù…Ø¯ÛŒØ±ÛŒØª Ù‡ÙˆØ´Ù…Ù†Ø¯ VLESS Ø¨Ø§ Xray
<br>
XHTTP + WebSocket
</div>

<div class="powered">
POWERED BY YASIN BEHZAD
</div>

<div class="status">

<span
    class="status-dot ${
        online ? "online" : ""
    }"
></span>

Xray ${
    online
        ? "ONLINE"
        : "OFFLINE"
}

</div>

</div>

<div class="flame"></div>
<div class="sword"></div>

</div>

<div class="grid">

<div class="card">

<div class="stat-label">
Ú©Ø§Ø±Ø¨Ø±Ø§Ù†
</div>

<div class="stat-value">
${users.length}
</div>

</div>

<div class="card">

<div class="stat-label">
Ú©Ø§Ø±Ø¨Ø±Ø§Ù† ÙØ¹Ø§Ù„
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

<div class="section-title">

<div>

<h2>
ðŸ‘¤ Ú©Ø§Ø±Ø¨Ø±Ø§Ù†
</h2>

<div class="muted">
Ù…Ø¯ÛŒØ±ÛŒØª Ø®ÙˆØ¯Ú©Ø§Ø± Ú©Ø§Ù†ÙÛŒÚ¯â€ŒÙ‡Ø§ÛŒ Xray
</div>

</div>

<a
    class="btn primary"
    href="/users/new"
>
ï¼‹ Ú©Ø§Ø±Ø¨Ø± Ø¬Ø¯ÛŒØ¯
</a>

</div>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>
Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ
</th>

<th>
Ù¾Ø±ÙˆØªÚ©Ù„
</th>

<th>
ÙˆØ¶Ø¹ÛŒØª
</th>

<th>
Ú©Ø§Ù†ÙÛŒÚ¯
</th>

<th>
Ø¹Ù…Ù„ÛŒØ§Øª
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

<td>

${
    user.status === "active"
        ? `
<span class="badge green">
â— ÙØ¹Ø§Ù„
</span>
`
        : `
<span class="badge red">
â— ØºÛŒØ±ÙØ¹Ø§Ù„
</span>
`
}

</td>

<td>

<a
    class="btn"
    href="/users/config?id=${user.id}"
>
âš™ï¸ Ú©Ø§Ù†ÙÛŒÚ¯
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
        ? "Ø®Ø§Ù…ÙˆØ´"
        : "ÙØ¹Ø§Ù„"
}

</button>

</form>

<form
    method="POST"
    action="/users/delete"
    onsubmit="return confirm('Ø§ÛŒÙ† Ú©Ø§Ø±Ø¨Ø± Ø­Ø°Ù Ø´ÙˆØ¯ØŸ')"
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
Ø­Ø°Ù
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
    class="muted"
>
Ù‡Ù†ÙˆØ² Ú©Ø§Ø±Ø¨Ø±ÛŒ Ø³Ø§Ø®ØªÙ‡ Ù†Ø´Ø¯Ù‡ Ø§Ø³Øª.
</td>

</tr>
`
}

</tbody>

</table>

</div>

</div>

<div class="footer">
VERGILPANEL v${VERSION} Â· POWERED BY YASIN BEHZAD
</div>

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

<a
    href="/dashboard"
    class="brand"
>
âš”ï¸ VERGIL<span>PANEL</span>
</a>

<a
    class="btn"
    href="/dashboard"
>
â† Ø¯Ø§Ø´Ø¨ÙˆØ±Ø¯
</a>

</div>

<div class="card form">

<div class="settings-icon">
ðŸ‘¤
</div>

<h1>
Ø³Ø§Ø®Øª Ú©Ø§Ø±Ø¨Ø±
</h1>

<p class="muted">
UUID Ùˆ Subscription Ø¨Ù‡ ØµÙˆØ±Øª Ø®ÙˆØ¯Ú©Ø§Ø± Ø³Ø§Ø®ØªÙ‡ Ù…ÛŒâ€ŒØ´ÙˆÙ†Ø¯.
</p>

${
    error
        ? `
<div class="notice">
${escapeHtml(error)}
</div>
`
        : ""
}

<form
    method="POST"
    action="/users/new"
>

<label>
Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ
</label>

<input
    name="username"
    required
    maxlength="64"
    placeholder="User-01"
    dir="ltr"
>

<label>
Ù…Ø­Ø¯ÙˆØ¯ÛŒØª ØªØ±Ø§ÙÛŒÚ©
</label>

<select name="traffic_limit">

<option value="0">
Ù†Ø§Ù…Ø­Ø¯ÙˆØ¯
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
ØªØ§Ø±ÛŒØ® Ø§Ù†Ù‚Ø¶Ø§
</label>

<input
    type="datetime-local"
    name="expires_at"
    dir="ltr"
>

<br><br>

<button
    class="btn primary"
    type="submit"
>
âš”ï¸ Ø³Ø§Ø®Øª Ú©Ø§Ø±Ø¨Ø±
</button>

</form>

</div>

</div>
`
    );
}

function settingsPage(
    req,
    message = "",
    error = ""
) {
    const admin =
        getAdmin();

    return layout(
        "Settings",
        `
<div class="container">

<div class="nav">

<a
    href="/dashboard"
    class="brand"
>
âš”ï¸ VERGIL<span>PANEL</span>
</a>

<a
    class="btn"
    href="/dashboard"
>
â† Ø¯Ø§Ø´Ø¨ÙˆØ±Ø¯
</a>

</div>

<div class="card form">

<div class="settings-icon">
âš™ï¸
</div>

<h1>
ØªÙ†Ø¸ÛŒÙ…Ø§Øª Ù…Ø¯ÛŒØ±
</h1>

<p class="muted">
Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ Ùˆ Ø±Ù…Ø² Ø¹Ø¨ÙˆØ± ÙˆØ±ÙˆØ¯ Ø¨Ù‡ Ù¾Ù†Ù„ Ø±Ø§ ØªØºÛŒÛŒØ± Ø¯Ù‡ÛŒØ¯.
</p>

${
    message
        ? `
<div class="notice">
âœ… ${escapeHtml(message)}
</div>
`
        : ""
}

${
    error
        ? `
<div class="notice">
âŒ ${escapeHtml(error)}
</div>
`
        : ""
}

<form
    method="POST"
    action="/settings"
>

<label>
Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ Ø¬Ø¯ÛŒØ¯
</label>

<input
    name="username"
    value="${escapeHtml(
        admin?.username || "admin"
    )}"
    required
    maxlength="64"
    dir="ltr"
>

<label>
Ø±Ù…Ø² Ø¹Ø¨ÙˆØ± Ø¬Ø¯ÛŒØ¯
</label>

<input
    type="password"
    name="password"
    placeholder="Ø­Ø¯Ø§Ù‚Ù„ 4 Ú©Ø§Ø±Ø§Ú©ØªØ±"
    minlength="4"
    dir="ltr"
>

<label>
ØªÚ©Ø±Ø§Ø± Ø±Ù…Ø² Ø¹Ø¨ÙˆØ±
</label>

<input
    type="password"
    name="password_confirm"
    placeholder="ØªÚ©Ø±Ø§Ø± Ø±Ù…Ø² Ø¹Ø¨ÙˆØ±"
    minlength="4"
    dir="ltr"
>

<br><br>

<button
    class="btn primary"
    type="submit"
>
ðŸ’¾ Ø°Ø®ÛŒØ±Ù‡ ØªØºÛŒÛŒØ±Ø§Øª
</button>

</form>

<br>

<div class="notice">

<strong>
ðŸ” Ø§Ø·Ù„Ø§Ø¹Ø§Øª ÙˆØ±ÙˆØ¯
</strong>

<br><br>

Ø§Ú¯Ø± Ø±Ù…Ø² Ø¹Ø¨ÙˆØ± Ø±Ø§ Ø®Ø§Ù„ÛŒ Ø¨Ú¯Ø°Ø§Ø±ÛŒØ¯ØŒ
Ø±Ù…Ø² ÙØ¹Ù„ÛŒ ØªØºÛŒÛŒØ± Ù†Ù…ÛŒâ€ŒÚ©Ù†Ø¯.

</div>

</div>

<div class="footer">
POWERED BY YASIN BEHZAD
</div>

</div>
`
    );
}

async function configPage(req, user) {
    const origin =
        getPublicOrigin(req);

    const links =
        makeVlessLinks(
            user,
            origin
        );

    const subscriptionUrl =
        `${origin}/sub/${user.subscription_token}`;

    const xhttpQr =
        await qrCode(
            links.xhttp
        );

    const wsQr =
        await qrCode(
            links.websocket
        );

    const subQr =
        await qrCode(
            subscriptionUrl
        );

    return layout(
        `${user.username} Config`,
        `
<div class="container">

<div class="nav">

<a
    href="/dashboard"
    class="brand"
>
âš”ï¸ VERGIL<span>PANEL</span>
</a>

<a
    class="btn"
    href="/dashboard"
>
â† Ø¯Ø§Ø´Ø¨ÙˆØ±Ø¯
</a>

</div>

<div class="card">

<h1>
âš”ï¸ ${escapeHtml(user.username)}
</h1>

<p class="muted">
VLESS Â· XHTTP + WebSocket
</p>

<div class="notice">

<strong>
ðŸ“¡ Subscription
</strong>

<pre class="config">${escapeHtml(
    subscriptionUrl
)}</pre>

<button
    class="btn primary"
    onclick='copyText(${JSON.stringify(
        subscriptionUrl
    )})'
>
ðŸ“‹ Ú©Ù¾ÛŒ Subscription
</button>

</div>

<div class="qr-grid">

<div class="qr-card">

<h3>
ðŸ“¡ Subscription QR
</h3>

<img
    src="${subQr}"
    alt="Subscription QR"
>

<br><br>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(
        subscriptionUrl
    )})'
>
Ú©Ù¾ÛŒ Ù„ÛŒÙ†Ú©
</button>

</div>

<div class="qr-card">

<h3>
ðŸ”¥ XHTTP QR
</h3>

<img
    src="${xhttpQr}"
    alt="XHTTP QR"
>

<br><br>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(
        links.xhttp
    )})'
>
Ú©Ù¾ÛŒ
</button>

</div>

</div>

<h2>
ðŸš€ VLESS + XHTTP
</h2>

<pre class="config">${escapeHtml(
    links.xhttp
)}</pre>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(
        links.xhttp
    )})'
>
ðŸ“‹ Copy XHTTP
</button>

<br><br>

<h2>
ðŸŒ VLESS + WebSocket
</h2>

<pre class="config">${escapeHtml(
    links.websocket
)}</pre>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(
        links.websocket
    )})'
>
ðŸ“‹ Copy WebSocket
</button>

<div class="qr-grid">

<div class="qr-card">

<h3>
ðŸ”¥ XHTTP
</h3>

<img
    src="${xhttpQr}"
    alt="XHTTP QR"
>

</div>

<div class="qr-card">

<h3>
ðŸŒ WebSocket
</h3>

<img
    src="${wsQr}"
    alt="WebSocket QR"
>

</div>

</div>

<br>

<div class="notice">

<strong>
ðŸ’™ Ø³Ø§Ø®ØªÙ‡ Ø´Ø¯Ù‡ ØªÙˆØ³Ø· ÛŒØ§Ø³ÛŒÙ†
</strong>

<br>

Ú©Ø§Ù…Ù„Ø§Ù‹ Ø±Ø§ÛŒÚ¯Ø§Ù† Ùˆ ØºÛŒØ±Ù‚Ø§Ø¨Ù„ ÙØ±ÙˆØ´

<br><br>

<span class="muted small">
Ø§ÛŒÙ† Ù¾ÛŒØ§Ù… Ø¯Ø§Ø®Ù„ Subscription Ù†ÛŒØ² Ù‚Ø±Ø§Ø± Ú¯Ø±ÙØªÙ‡ Ø§Ø³Øª.
</span>

</div>

<h2>
ðŸ†” UUID
</h2>

<pre class="config">${escapeHtml(
    user.uuid
)}</pre>

<div class="footer">
POWERED BY YASIN BEHZAD
</div>

</div>

</div>

<script>

async function copyText(text){

    try{

        await navigator.clipboard.writeText(text);

        alert("Ú©Ù¾ÛŒ Ø´Ø¯ âœ…");

    }catch{

        prompt(
            "Ù…ØªÙ† Ø±Ø§ Ú©Ù¾ÛŒ Ú©Ù†ÛŒØ¯:",
            text
        );

    }

}

</script>
`
    );
}

/*
 * Default Admin
 *
 * Fresh deployment:
 *
 * admin / admin
 *
 * Railway Variables can override it.
 */

function ensureDefaultAdmin() {

    const username =
        String(
            process.env.ADMIN_USERNAME || "admin"
        ).trim();

    const password =
        String(
            process.env.ADMIN_PASSWORD || "admin"
        );

    const existing =
        db.prepare(`
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
            `ðŸ‘¤ Admin ready: ${username}`
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
        `ðŸ‘¤ Default admin created: ${username}`
    );
}

function authenticate(
    username,
    password
) {
    const admin =
        db.prepare(`
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
            "Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ Ø§Ù„Ø²Ø§Ù…ÛŒ Ø§Ø³Øª."
        );
    }

    const exists =
        db.prepare(`
            SELECT id
            FROM users
            WHERE username = ?
        `).get(username);

    if (exists) {
        throw new Error(
            "Ø§ÛŒÙ† Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ Ù‚Ø¨Ù„Ø§Ù‹ ÙˆØ¬ÙˆØ¯ Ø¯Ø§Ø±Ø¯."
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
                "ØªØ§Ø±ÛŒØ® Ø§Ù†Ù‚Ø¶Ø§ Ù†Ø§Ù…Ø¹ØªØ¨Ø± Ø§Ø³Øª."
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

function updateAdmin(
    username,
    password
) {
    const admin =
        getAdmin();

    if (!admin) {
        throw new Error(
            "Admin account not found."
        );
    }

    const cleanUsername =
        String(
            username || ""
        ).trim();

    if (!cleanUsername) {
        throw new Error(
            "Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ Ù†Ù…ÛŒâ€ŒØªÙˆØ§Ù†Ø¯ Ø®Ø§Ù„ÛŒ Ø¨Ø§Ø´Ø¯."
        );
    }

    if (
        cleanUsername !==
        admin.username
    ) {

        const duplicate =
            db.prepare(`
                SELECT id
                FROM admins
                WHERE username = ?
                AND id != ?
            `).get(
                cleanUsername,
                admin.id
            );

        if (duplicate) {
            throw new Error(
                "Ø§ÛŒÙ† Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ Ù‚Ø¨Ù„Ø§Ù‹ Ø§Ø³ØªÙØ§Ø¯Ù‡ Ø´Ø¯Ù‡ Ø§Ø³Øª."
            );
        }
    }

    if (password) {

        if (
            String(password).length < 4
        ) {
            throw new Error(
                "Ø±Ù…Ø² Ø¹Ø¨ÙˆØ± Ø¨Ø§ÛŒØ¯ Ø­Ø¯Ø§Ù‚Ù„ 4 Ú©Ø§Ø±Ø§Ú©ØªØ± Ø¨Ø§Ø´Ø¯."
            );
        }

        db.prepare(`
            UPDATE admins
            SET
                username = ?,
                password_hash = ?
            WHERE id = ?
        `).run(
            cleanUsername,
            hashPassword(password),
            admin.id
        );

    } else {

        db.prepare(`
            UPDATE admins
            SET username = ?
            WHERE id = ?
        `).run(
            cleanUsername,
            admin.id
        );
    }
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
        agent: proxyHttpAgent,
        headers: {
            ...req.headers,
            host: `127.0.0.1:${targetPort}`
        }
    };

    const proxy = http.request(options, upstream => {
        upstream.on("error", error => {
            console.error("HTTP upstream response error:", error);
            if (!res.destroyed) res.destroy(error);
        });

        res.writeHead(upstream.statusCode || 502, upstream.headers);
        upstream.pipe(res);
    });

    proxy.setTimeout(15000, () => {
        const error = new Error("Upstream request timed out");
        console.error("HTTP proxy timeout:", error.message);
        proxy.destroy(error);
    });

    proxy.on("error", error => {
        console.error("HTTP proxy error:", error);

        if (res.destroyed) return;
        if (!res.headersSent) {
            const status = error.message === "Upstream request timed out" ? 504 : 502;
            res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
            res.end(status === 504 ? "Gateway Timeout" : "Bad Gateway");
        } else {
            res.destroy(error);
        }
    });

    req.on("aborted", () => proxy.destroy());
    req.on("error", error => proxy.destroy(error));
    res.on("close", () => {
        if (!res.writableEnded) proxy.destroy();
    });
    res.on("error", error => proxy.destroy(error));
    req.pipe(proxy);
}

function proxyWebSocket(
    req,
    clientSocket,
    head
) {
    const upstream = net.connect({
        host: "127.0.0.1",
        port: XRAY_WS_PORT
    });
    let connected = false;

    upstream.setTimeout(10000, () => {
        const error = new Error("WebSocket upstream connection timed out");
        console.error("WebSocket proxy timeout:", error.message);
        if (!connected && !clientSocket.destroyed) {
            clientSocket.end("HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n");
        }
        upstream.destroy(error);
    });

    upstream.on("connect", () => {
        connected = true;
        upstream.setTimeout(0);
        upstream.setKeepAlive(true, 30000);

        const headers = [`${req.method} ${req.url} HTTP/${req.httpVersion}`];
        for (const [key, value] of Object.entries(req.headers)) {
            if (Array.isArray(value)) {
                for (const item of value) headers.push(`${key}: ${item}`);
            } else {
                headers.push(`${key}: ${value}`);
            }
        }

        headers.push("", "");
        try {
            upstream.write(headers.join("\r\n"));
            if (head && head.length) upstream.write(head);
            clientSocket.pipe(upstream);
            upstream.pipe(clientSocket);
        } catch (error) {
            console.error("WebSocket proxy forwarding error:", error);
            clientSocket.destroy();
            upstream.destroy();
        }
    });

    upstream.on("error", error => {
        console.error("WebSocket proxy error:", error);
        if (!clientSocket.destroyed) {
            if (!connected) {
                clientSocket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
            } else {
                clientSocket.destroy();
            }
        }
    });

    upstream.on("close", () => {
        if (!clientSocket.destroyed) clientSocket.end();
    });

    clientSocket.on("error", error => {
        console.error("WebSocket client socket error:", error);
        upstream.destroy();
    });

    clientSocket.on("close", () => upstream.destroy());
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

    if (
        user.expires_at &&
        user.expires_at <= nowIso()
    ) {

        sendJson(
            res,
            {
                ok: false,
                error:
                    "Subscription expired."
            },
            403
        );

        return;
    }

    const content =
        makeSubscription(
            user,
            getPublicOrigin(req)
        );

    res.writeHead(
        200,
        {
            "Content-Type":
                "text/plain; charset=utf-8",

            "Cache-Control":
                "no-store"
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
                pathname.slice(5);

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
            const processOk = Boolean(
                xrayProcess &&
                !xrayProcess.killed &&
                xrayProcess.exitCode === null
            );
            const [xhttp, websocket] = await Promise.all([
                checkTcpPort(XRAY_XHTTP_PORT),
                checkTcpPort(XRAY_WS_PORT)
            ]);
            const ok = processOk && xhttp && websocket;

            sendJson(
                res,
                {
                    ok,
                    panel: VERSION,
                    process: processOk,
                    xhttp,
                    websocket,
                    transports: [
                        "xhttp",
                        "websocket"
                    ]
                },
                ok ? 200 : 503
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

            if (getSession(req)) {

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

                sendHtml(
                    res,
                    loginPage(
                        "Ù†Ø§Ù… Ú©Ø§Ø±Ø¨Ø±ÛŒ ÛŒØ§ Ø±Ù…Ø² Ø¹Ø¨ÙˆØ± Ø§Ø´ØªØ¨Ø§Ù‡ Ø§Ø³Øª."
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

            /*
             * Ø§Ú¯Ø± ÙˆØ±ÙˆØ¯ Ø¨Ø§ admin/admin Ø¨Ø§Ø´Ø¯ØŒ
             * Ú©Ø§Ø±Ø¨Ø± Ø±Ø§ Ø¨Ø±Ø§ÛŒ ØªØºÛŒÛŒØ± Ø§Ø·Ù„Ø§Ø¹Ø§Øª Ø¨Ù‡ Settings Ù…ÛŒâ€ŒÙØ±Ø³ØªÛŒÙ….
             */

            const admin =
                getAdmin();

            const isDefaultLogin =
                admin &&
                username === "admin" &&
                password === "admin";

            res.writeHead(
                302,
                {
                    Location:
                        isDefaultLogin
                            ? "/settings"
                            : "/dashboard",

                    "Set-Cookie":
                        `vergil_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Secure`
                }
            );

            res.end();

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
                    Location: "/login",

                    "Set-Cookie":
                        "vergil_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure"
                }
            );

            res.end();

            return;
        }

        /*
         * Protected routes
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
         * Settings
         */

        if (
            pathname === "/settings" &&
            req.method === "GET"
        ) {

            sendHtml(
                res,
                settingsPage(req)
            );

            return;
        }

        if (
            pathname === "/settings" &&
            req.method === "POST"
        ) {

            try {

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

                const confirm =
                    String(
                        form.get(
                            "password_confirm"
                        ) || ""
                    );

                if (
                    password &&
                    password !== confirm
                ) {

                    throw new Error(
                        "Ø±Ù…Ø²Ù‡Ø§ÛŒ Ø¹Ø¨ÙˆØ± ÛŒÚ©Ø³Ø§Ù† Ù†ÛŒØ³ØªÙ†Ø¯."
                    );
                }

                updateAdmin(
                    username,
                    password
                );

                /*
                 * ØªÙ…Ø§Ù… SessionÙ‡Ø§ÛŒ Ù‚Ø¨Ù„ÛŒ Ø­Ø°Ù Ù…ÛŒâ€ŒØ´ÙˆÙ†Ø¯
                 * ØªØ§ Ø¨Ø§ Ø§Ø·Ù„Ø§Ø¹Ø§Øª Ø¬Ø¯ÛŒØ¯ Ø¯ÙˆØ¨Ø§Ø±Ù‡ Login Ø´ÙˆØ¯.
                 */

                sessions.clear();

                redirect(
                    res,
                    "/login"
                );

            } catch (error) {

                sendHtml(
                    res,
                    settingsPage(
                        req,
                        "",
                        error?.message ||
                            "Ø®Ø·Ø§ Ø¯Ø± Ø°Ø®ÛŒØ±Ù‡ ØªÙ†Ø¸ÛŒÙ…Ø§Øª."
                    ),
                    400
                );
            }

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
                    `ðŸ‘¤ User created: ${user.username}`
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
                        "Ø®Ø·Ø§ Ø¯Ø± Ø³Ø§Ø®Øª Ú©Ø§Ø±Ø¨Ø±."
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
                    url.searchParams.get("id")
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
                        "404",
                        `
<div class="container">

<div class="card">

<h1>
Ú©Ø§Ø±Ø¨Ø± Ù¾ÛŒØ¯Ø§ Ù†Ø´Ø¯
</h1>

<a
    class="btn"
    href="/dashboard"
>
Ø¯Ø§Ø´Ø¨ÙˆØ±Ø¯
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
         * Toggle
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
         * Delete
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

<h1>
404
</h1>

<p class="muted">
ØµÙØ­Ù‡ Ù…ÙˆØ±Ø¯ Ù†Ø¸Ø± Ù¾ÛŒØ¯Ø§ Ù†Ø´Ø¯.
</p>

<a
    class="btn"
    href="/dashboard"
>
Ø¨Ø§Ø²Ú¯Ø´Øª
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

const server =
    http.createServer(
        handleRequest
    );

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
            `âš”ï¸ VergilPanel v${VERSION} running on ${HOST}:${PORT}`
        );

        console.log(
            `ðŸ‘¤ Login: admin / admin`
        );

        console.log(
            `ðŸ’™ POWERED BY YASIN BEHZAD`
        );

        console.log(
            `âš”ï¸ Railway TCP Proxy NOT required`
        );
    }
);

async function shutdown(signal) {

    console.log(
        `Received ${signal}`
    );

    stoppingXray = true;
    clearXrayRestartTimer();

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
