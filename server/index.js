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

const VERSION = "0.9.0";

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

/*
 * ---------------------------------------------------------
 * Database migration
 * ---------------------------------------------------------
 *
 * کاربران قدیمی v0.8.0 این ستون‌ها را ندارند.
 * در اولین اجرای v0.9.0 ستون‌ها خودکار ساخته می‌شوند.
 */

function addColumnIfMissing(
    table,
    column,
    definition
) {
    const columns =
        db.prepare(
            `PRAGMA table_info(${table})`
        ).all();

    const exists =
        columns.some(
            item => item.name === column
        );

    if (!exists) {
        db.exec(
            `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
        );
    }
}

addColumnIfMissing(
    "users",
    "xhttp_paths",
    "TEXT"
);

addColumnIfMissing(
    "users",
    "ws_paths",
    "TEXT"
);

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");
}

function randomToken(bytes = 32) {
    return crypto
        .randomBytes(bytes)
        .toString("hex");
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
    const header =
        req.headers.cookie || "";

    const result = {};

    for (
        const part
        of header.split(";")
    ) {
        const index =
            part.indexOf("=");

        if (index === -1) continue;

        const key =
            part.slice(0, index).trim();

        const value =
            part.slice(index + 1).trim();

        try {
            result[key] =
                decodeURIComponent(value);
        } catch {
            result[key] = value;
        }
    }

    return result;
}

function getSession(req) {
    const cookies =
        parseCookies(req);

    if (!cookies.vergil_session) {
        return null;
    }

    return (
        sessions.get(
            cookies.vergil_session
        ) || null
    );
}

function redirect(
    res,
    location
) {
    res.writeHead(
        302,
        {
            Location: location,
            "Cache-Control":
                "no-store"
        }
    );

    res.end();
}

function sendHtml(
    res,
    html,
    status = 200
) {
    res.writeHead(
        status,
        {
            "Content-Type":
                "text/html; charset=utf-8",

            "Cache-Control":
                "no-store"
        }
    );

    res.end(html);
}

function sendJson(
    res,
    data,
    status = 200
) {
    res.writeHead(
        status,
        {
            "Content-Type":
                "application/json; charset=utf-8",

            "Cache-Control":
                "no-store"
        }
    );

    res.end(
        JSON.stringify(data)
    );
}

async function readBody(req) {
    return new Promise(
        (resolve, reject) => {
            let body = "";

            req.on(
                "data",
                chunk => {
                    body += chunk;

                    if (
                        body.length >
                        1024 * 1024
                    ) {
                        reject(
                            new Error(
                                "Request body too large"
                            )
                        );

                        req.destroy();
                    }
                }
            );

            req.on(
                "end",
                () => resolve(body)
            );

            req.on(
                "error",
                reject
            );
        }
    );
}

async function readForm(req) {
    return new URLSearchParams(
        await readBody(req)
    );
}

function requireAuth(
    req,
    res
) {
    const session =
        getSession(req);

    if (!session) {
        redirect(
            res,
            "/login"
        );

        return null;
    }

    return session;
}

function getPublicHost(req) {
    const forwarded =
        req.headers[
            "x-forwarded-host"
        ];

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
    const host =
        getPublicHost(req);

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
    `).all(
        nowIso()
    );
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

/*
 * ---------------------------------------------------------
 * Random per-user Paths
 * ---------------------------------------------------------
 */

const PATH_ALPHABET =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

function randomPath(
    prefix
) {
    let value = "";

    for (
        let i = 0;
        i < 16;
        i++
    ) {
        value +=
            PATH_ALPHABET[
                crypto.randomInt(
                    0,
                    PATH_ALPHABET.length
                )
            ];
    }

    return `/${prefix}-${value}`;
}

function generateUserPaths() {
    return {
        xhttp: [
            randomPath("xhttp"),
            randomPath("xhttp"),
            randomPath("xhttp")
        ],

        ws: [
            randomPath("ws"),
            randomPath("ws"),
            randomPath("ws")
        ]
    };
}

function saveUserPaths(
    userId,
    paths
) {
    db.prepare(`
        UPDATE users
        SET
            xhttp_paths = ?,
            ws_paths = ?
        WHERE id = ?
    `).run(
        JSON.stringify(
            paths.xhttp
        ),
        JSON.stringify(
            paths.ws
        ),
        Number(userId)
    );
}

function getUserPaths(user) {
    let xhttp = [];
    let ws = [];

    try {
        xhttp =
            JSON.parse(
                user.xhttp_paths || "[]"
            );
    } catch {
        xhttp = [];
    }

    try {
        ws =
            JSON.parse(
                user.ws_paths || "[]"
            );
    } catch {
        ws = [];
    }

    if (
        !Array.isArray(xhttp) ||
        xhttp.length !== 3
    ) {
        xhttp = [];
    }

    if (
        !Array.isArray(ws) ||
        ws.length !== 3
    ) {
        ws = [];
    }

    return {
        xhttp,
        ws
    };
}

function ensureUserPaths(
    user
) {
    const current =
        getUserPaths(user);

    if (
        current.xhttp.length === 3 &&
        current.ws.length === 3
    ) {
        return current;
    }

    const paths =
        generateUserPaths();

    saveUserPaths(
        user.id,
        paths
    );

    return paths;
}

function ensureAllUserPaths() {
    const users =
        db.prepare(`
            SELECT *
            FROM users
        `).all();

    for (
        const user
        of users
    ) {
        ensureUserPaths(user);
    }

    console.log(
        `🛣️ User paths synced: ${users.length} user(s)`
    );
}

/*
 * ---------------------------------------------------------
 * Xray configuration
 * ---------------------------------------------------------
 *
 * Xray همچنان فقط دو inbound داخلی دارد.
 * Pathهای اختصاصی توسط Node به این دو Path داخلی
 * ترجمه می‌شوند.
 */

function generateXrayConfig() {
    const clients =
        activeUsers().map(
            user => ({
                id: user.uuid,
                email: user.username
            })
        );

    return {
        log: {
            loglevel: "warning"
        },

        inbounds: [
            {
                listen:
                    "127.0.0.1",

                port:
                    XRAY_XHTTP_PORT,

                protocol:
                    "vless",

                settings: {
                    clients,
                    decryption:
                        "none"
                },

                streamSettings: {
                    network:
                        "xhttp",

                    security:
                        "none",

                    xhttpSettings: {
                        path:
                            XHTTP_PATH,

                        mode:
                            "auto"
                    }
                }
            },

            {
                listen:
                    "127.0.0.1",

                port:
                    XRAY_WS_PORT,

                protocol:
                    "vless",

                settings: {
                    clients,
                    decryption:
                        "none"
                },

                streamSettings: {
                    network:
                        "websocket",

                    security:
                        "none",

                    wsSettings: {
                        path:
                            WS_PATH
                    }
                }
            }
        ],

        outbounds: [
            {
                protocol:
                    "freedom"
            }
        ]
    };
}

async function writeXrayConfig() {
    const config =
        generateXrayConfig();

    await fs.writeFile(
        XRAY_CONFIG,
        JSON.stringify(
            config,
            null,
            2
        ),
        "utf8"
    );

    console.log(
        `⚙️ Xray config synced: ${activeUsers().length} active user(s)`
    );
}

function stopXray() {
    return new Promise(
        resolve => {
            if (!xrayProcess) {
                resolve();
                return;
            }

            const processToStop =
                xrayProcess;

            xrayProcess = null;

            const timer =
                setTimeout(
                    () => {
                        try {
                            processToStop.kill(
                                "SIGKILL"
                            );
                        } catch {}

                        resolve();
                    },
                    3000
                );

            processToStop.once(
                "exit",
                () => {
                    clearTimeout(
                        timer
                    );

                    resolve();
                }
            );

            try {
                processToStop.kill(
                    "SIGTERM"
                );
            } catch {
                clearTimeout(
                    timer
                );

                resolve();
            }
        }
    );
}

async function startXray() {
    await writeXrayConfig();

    console.log(
        `⚙️ Xray binary: ${XRAY_BIN}`
    );

    xrayProcess =
        spawn(
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

    xrayProcess.stdout.on(
        "data",
        data => {
            process.stdout.write(
                `[XRAY] ${data}`
            );
        }
    );

    xrayProcess.stderr.on(
        "data",
        data => {
            process.stderr.write(
                `[XRAY] ${data}`
            );
        }
    );

    xrayProcess.on(
        "error",
        error => {
            console.error(
                "❌ Xray process error:",
                error
            );
        }
    );

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
                    () => {
                        startXray()
                            .catch(
                                error => {
                                    console.error(
                                        "❌ Xray restart failed:",
                                        error
                                    );
                                }
                            );
                    },
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
 * ---------------------------------------------------------
 * VLESS links
 * ---------------------------------------------------------
 */

function makeVlessLinks(
    user,
    origin
) {
    const domain =
        new URL(origin).hostname;

    const paths =
        ensureUserPaths(user);

    const xhttpLinks =
        paths.xhttp.map(
            (
                path,
                index
            ) => {
                const params =
                    new URLSearchParams({
                        encryption:
                            "none",

                        security:
                            "tls",

                        type:
                            "xhttp",

                        path,

                        host:
                            domain,

                        mode:
                            "auto"
                    });

                return (
                    `vless://${user.uuid}@${domain}:443?${params.toString()}#${encodeURIComponent(
                        user.username
                    )}-XHTTP-${index + 1}`
                );
            }
        );

    const websocketLinks =
        paths.ws.map(
            (
                path,
                index
            ) => {
                const params =
                    new URLSearchParams({
                        encryption:
                            "none",

                        security:
                            "tls",

                        type:
                            "ws",

                        path,

                        host:
                            domain
                    });

                return (
                    `vless://${user.uuid}@${domain}:443?${params.toString()}#${encodeURIComponent(
                        user.username
                    )}-WS-${index + 1}`
                );
            }
        );

    return {
        xhttp:
            xhttpLinks[0],

        websocket:
            websocketLinks[0],

        xhttpLinks,

        websocketLinks
    };
}

/*
 * ---------------------------------------------------------
 * Dummy / Branding configurations
 * ---------------------------------------------------------
 */

function makeDummyConfig(
    message
) {
    const params =
        new URLSearchParams({
            encryption:
                "none",

            security:
                "none",

            type:
                "tcp"
        });

    return (
        `vless://00000000-0000-0000-0000-000000000000@0.0.0.0:443?${params.toString()}#${encodeURIComponent(
            message
        )}`
    );
}

function makeSubscription(
    user,
    origin
) {
    const links =
        makeVlessLinks(
            user,
            origin
        );

    const dummy1 =
        makeDummyConfig(
            "ساخته شده توسط یاسین - کاملا رایگان و غیرقابل فروش"
        );

    const dummy2 =
        makeDummyConfig(
            "به یاد زنده یاد علی نور"
        );

    return Buffer.from(
        [
            ...links.xhttpLinks,
            ...links.websocketLinks,
            dummy1,
            dummy2
        ].join("\n"),
        "utf8"
    ).toString("base64");
}

async function qrCode(text) {
    return QRCode.toDataURL(
        text,
        {
            width: 260,
            margin: 2,
            errorCorrectionLevel:
                "M"
        }
    );
}

/*
 * ---------------------------------------------------------
 * UI
 * ---------------------------------------------------------
 */

function layout(
    title,
    body
) {
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

function loginPage(
    error = ""
) {
    return layout(
        "Login",
        `
<div class="login">

<div class="card login-card">

<div class="login-logo">
⚔️ VERGIL<span>PANEL</span>
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
نام کاربری
</label>

<input
    name="username"
    required
    autocomplete="username"
    dir="ltr"
>

<label>
رمز عبور
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
ورود به پنل
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
    const users =
        allUsers();

    const active =
        activeUsers();

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
⚔️
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

<div class="hero-content">

<div class="hero-kicker">
XRAY MANAGEMENT SYSTEM
</div>

<div class="hero-title">
VERGIL
</div>

<div class="hero-sub">
مدیریت هوشمند VLESS با Xray
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
کاربران
</div>

<div class="stat-value">
${users.length}
</div>

</div>

<div class="card">

<div class="stat-label">
کاربران فعال
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
👤 کاربران
</h2>

<div class="muted">
مدیریت خودکار کانفیگ‌های Xray
</div>

</div>

<a
    class="btn primary"
    href="/users/new"
>
＋ کاربر جدید
</a>

</div>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>
نام کاربری
</th>

<th>
پروتکل
</th>

<th>
وضعیت
</th>

<th>
کانفیگ
</th>

<th>
عملیات
</th>

</tr>

</thead>

<tbody>

${
    users.length
        ? users.map(
            user => `

<tr>

<td>
<strong>
${escapeHtml(
    user.username
)}
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
● فعال
</span>
`
        : `
<span class="badge red">
● غیرفعال
</span>
`
}

</td>

<td>

<a
    class="btn"
    href="/users/config?id=${user.id}"
>
⚙️ کانفیگ
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
        ? "خاموش"
        : "فعال"
}

</button>

</form>

<form
    method="POST"
    action="/users/delete"
    onsubmit="return confirm('این کاربر حذف شود؟')"
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

`
        ).join("")
        : `
<tr>

<td
    colspan="5"
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
VERGILPANEL v${VERSION} · POWERED BY YASIN BEHZAD
</div>

</div>
`
    );
}

function newUserPage(
    error = ""
) {
    return layout(
        "New User",
        `
<div class="container">

<div class="nav">

<a
    href="/dashboard"
    class="brand"
>
⚔️ VERGIL<span>PANEL</span>
</a>

<a
    class="btn"
    href="/dashboard"
>
← داشبورد
</a>

</div>

<div class="card form">

<div class="settings-icon">
👤
</div>

<h1>
ساخت کاربر
</h1>

<p class="muted">
UUID و Subscription به صورت خودکار ساخته می‌شوند.
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
نام کاربری
</label>

<input
    name="username"
    required
    maxlength="64"
    placeholder="User-01"
    dir="ltr"
>

<label>
محدودیت ترافیک
</label>

<select name="traffic_limit">

<option value="0">
نامحدود
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
تاریخ انقضا
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
⚔️ ساخت کاربر
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
⚔️ VERGIL<span>PANEL</span>
</a>

<a
    class="btn"
    href="/dashboard"
>
← داشبورد
</a>

</div>

<div class="card form">

<div class="settings-icon">
⚙️
</div>

<h1>
تنظیمات مدیر
</h1>

<p class="muted">
نام کاربری و رمز عبور ورود به پنل را تغییر دهید.
</p>

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

<label>
نام کاربری جدید
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
رمز عبور جدید
</label>

<input
    type="password"
    name="password"
    placeholder="حداقل 4 کاراکتر"
    minlength="4"
    dir="ltr"
>

<label>
تکرار رمز عبور
</label>

<input
    type="password"
    name="password_confirm"
    placeholder="تکرار رمز عبور"
    minlength="4"
    dir="ltr"
>

<br><br>

<button
    class="btn primary"
    type="submit"
>
💾 ذخیره تغییرات
</button>

</form>

<br>

<div class="notice">

<strong>
🔐 اطلاعات ورود
</strong>

<br><br>

اگر رمز عبور را خالی بگذارید،
رمز فعلی تغییر نمی‌کند.

</div>

</div>

<div class="footer">
POWERED BY YASIN BEHZAD
</div>

</div>
`
    );
}

async function configPage(
    req,
    user
) {
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
⚔️ VERGIL<span>PANEL</span>
</a>

<a
    class="btn"
    href="/dashboard"
>
← داشبورد
</a>

</div>

<div class="card">

<h1>
⚔️ ${escapeHtml(
    user.username
)}
</h1>

<p class="muted">
VLESS · XHTTP + WebSocket
</p>

<div class="notice">

<strong>
📡 Subscription
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
📋 کپی Subscription
</button>

</div>

<div class="qr-grid">

<div class="qr-card">

<h3>
📡 Subscription QR
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
کپی لینک
</button>

</div>

<div class="qr-card">

<h3>
🔥 XHTTP QR
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
کپی
</button>

</div>

</div>

<h2>
🚀 VLESS + XHTTP
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
📋 Copy XHTTP
</button>

<br><br>

<h2>
🌐 VLESS + WebSocket
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
📋 Copy WebSocket
</button>

<div class="qr-grid">

<div class="qr-card">

<h3>
🔥 XHTTP
</h3>

<img
    src="${xhttpQr}"
    alt="XHTTP QR"
>

</div>

<div class="qr-card">

<h3>
🌐 WebSocket
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
💙 ساخته شده توسط یاسین
</strong>

<br>

کاملاً رایگان و غیرقابل فروش

<br><br>

<span class="muted small">
این پیام داخل Subscription نیز قرار گرفته است.
</span>

</div>

<h2>
🆔 UUID
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
 * ---------------------------------------------------------
 * Default Admin
 * ---------------------------------------------------------
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

    const existing =
        db.prepare(`
            SELECT id
            FROM admins
            WHERE username = ?
        `).get(
            username
        );

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
            `👤 Admin ready: ${username}`
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

function authenticate(
    username,
    password
) {
    const admin =
        db.prepare(`
            SELECT *
            FROM admins
            WHERE username = ?
        `).get(
            username
        );

    if (!admin) {
        return false;
    }

    return (
        admin.password_hash ===
        hashPassword(password)
    );
}

/*
 * ---------------------------------------------------------
 * User management
 * ---------------------------------------------------------
 */

async function createUser(
    form
) {
    const username =
        String(
            form.get("username") || ""
        ).trim();

    if (!username) {
        throw new Error(
            "نام کاربری الزامی است."
        );
    }

    const exists =
        db.prepare(`
            SELECT id
            FROM users
            WHERE username = ?
        `).get(
            username
        );

    if (exists) {
        throw new Error(
            "این نام کاربری قبلاً وجود دارد."
        );
    }

    const uuid =
        crypto.randomUUID();

    const subscriptionToken =
        randomToken(32);

    const trafficLimit =
        Number(
            form.get(
                "traffic_limit"
            ) || 0
        );

    let expiresAt = null;

    const expiry =
        String(
            form.get(
                "expires_at"
            ) || ""
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

    const createdUser =
        db.prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `).get(
            result.lastInsertRowid
        );

    /*
     * برای کاربر جدید، ۶ Path اختصاصی
     * همین‌جا یک‌بار ساخته و ذخیره می‌شوند.
     */

    ensureUserPaths(
        createdUser
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

async function deleteUser(
    id
) {
    db.prepare(`
        DELETE FROM users
        WHERE id = ?
    `).run(
        Number(id)
    );

    await restartXray();
}

async function toggleUser(
    id
) {
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
            "نام کاربری نمی‌تواند خالی باشد."
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
                "این نام کاربری قبلاً استفاده شده است."
            );
        }
    }

    if (password) {

        if (
            String(password).length < 4
        ) {
            throw new Error(
                "رمز عبور باید حداقل 4 کاراکتر باشد."
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

/*
 * ---------------------------------------------------------
 * Path routing
 * ---------------------------------------------------------
 *
 * Public random paths:
 *
 * /xhttp-xxxxxxxxxxxxxxxx
 * /ws-xxxxxxxxxxxxxxxx
 *
 * Internal Xray paths:
 *
 * /xhttp
 * /ws
 */

function findPathRoute(
    pathname
) {
    const users =
        activeUsers();

    for (
        const user
        of users
    ) {
        const paths =
            ensureUserPaths(
                user
            );

        if (
            paths.xhttp.includes(
                pathname
            )
        ) {
            return {
                type: "xhttp",
                targetPath:
                    XHTTP_PATH,
                user
            };
        }

        if (
            paths.ws.includes(
                pathname
            )
        ) {
            return {
                type: "ws",
                targetPath:
                    WS_PATH,
                user
            };
        }
    }

    return null;
}

/*
 * ---------------------------------------------------------
 * HTTP proxy
 * ---------------------------------------------------------
 */

function proxyHttpToXray(
    req,
    res,
    targetPort,
    targetPath
) {
    const requestUrl =
        new URL(
            req.url,
            `http://${req.headers.host || "localhost"}`
        );

    requestUrl.pathname =
        targetPath;

    const options = {
        hostname:
            "127.0.0.1",

        port:
            targetPort,

        path:
            requestUrl.pathname +
            requestUrl.search,

        method:
            req.method,

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
                    upstream.statusCode ||
                        502,

                    upstream.headers
                );

                upstream.pipe(
                    res
                );
            }
        );

    proxy.on(
        "error",
        error => {

            console.error(
                "HTTP proxy error:",
                error
            );

            if (
                !res.headersSent
            ) {

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
 * ---------------------------------------------------------
 * WebSocket proxy
 * ---------------------------------------------------------
 */

function proxyWebSocket(
    req,
    clientSocket,
    head,
    targetPath
) {
    const upstream =
        net.connect({
            host:
                "127.0.0.1",

            port:
                XRAY_WS_PORT
        });

    upstream.on(
        "connect",
        () => {

            const requestUrl =
                new URL(
                    req.url,
                    `http://${req.headers.host || "localhost"}`
                );

            requestUrl.pathname =
                targetPath;

            const headers = [];

            headers.push(
                `${req.method} ${requestUrl.pathname}${requestUrl.search} HTTP/${req.httpVersion}`
            );

            for (
                const [
                    key,
                    value
                ]
                of Object.entries(
                    req.headers
                )
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
                headers.join(
                    "\r\n"
                )
            );

            if (
                head &&
                head.length
            ) {
                upstream.write(
                    head
                );
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
 * ---------------------------------------------------------
 * Subscription
 * ---------------------------------------------------------
 */

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
        `).get(
            token
        );

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

    res.end(
        content
    );
}

/*
 * ---------------------------------------------------------
 * Main request handler
 * ---------------------------------------------------------
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

        const pathname =
            url.pathname;

        /*
         * Multi-path XHTTP
         */

        const pathRoute =
            findPathRoute(
                pathname
            );

        if (
            pathRoute &&
            pathRoute.type ===
                "xhttp"
        ) {

            proxyHttpToXray(
                req,
                res,
                XRAY_XHTTP_PORT,
                pathRoute.targetPath
            );

            return;
        }

        /*
         * Subscription
         */

        if (
            pathname.startsWith(
                "/sub/"
            )
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
            pathname ===
            "/health"
        ) {

            sendJson(
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
                        "نام کاربری یا رمز عبور اشتباه است."
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
             * اگر ورود با admin/admin باشد،
             * کاربر را برای تغییر اطلاعات به Settings می‌فرستیم.
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
                            "password_confirm"
                        ) || ""
                    );

                if (
                    password &&
                    password !== confirm
                ) {

                    throw new Error(
                        "رمزهای عبور یکسان نیستند."
                    );
                }

                updateAdmin(
                    username,
                    password
                );

                /*
                 * تمام Sessionهای قبلی حذف می‌شوند
                 * تا با اطلاعات جدید دوباره Login شود.
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
                            "خطا در ذخیره تنظیمات."
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
            pathname ===
                "/users/new" &&
            req.method === "GET"
        ) {

            sendHtml(
                res,
                newUserPage()
            );

            return;
        }

        if (
            pathname ===
                "/users/new" &&
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
                    `👤 User created: ${user.username}`
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
                            "خطا در ساخت کاربر."
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
            pathname ===
                "/users/config" &&
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
                `).get(
                    id
                );

            if (!user) {

                sendHtml(
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

                return;
            }

            /*
             * اگر کاربر قدیمی باشد،
             * همین‌جا هم Pathها ساخته می‌شوند.
             */

            ensureUserPaths(
                user
            );

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
            pathname ===
                "/users/toggle" &&
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
            pathname ===
                "/users/delete" &&
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
صفحه مورد نظر پیدا نشد.
</p>

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

/*
 * ---------------------------------------------------------
 * HTTP server
 * ---------------------------------------------------------
 */

const server =
    http.createServer(
        handleRequest
    );

/*
 * WebSocket random-path routing
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

            const route =
                findPathRoute(
                    url.pathname
                );

            if (
                route &&
                route.type === "ws"
            ) {

                proxyWebSocket(
                    req,
                    socket,
                    head,
                    route.targetPath
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
 * ---------------------------------------------------------
 * Startup
 * ---------------------------------------------------------
 */

ensureDefaultAdmin();

/*
 * کاربران قدیمی v0.8.0 هم
 * Path اختصاصی دریافت می‌کنند.
 */

ensureAllUserPaths();

await startXray();

server.listen(
    PORT,
    HOST,
    () => {

        console.log(
            `⚔️ VergilPanel v${VERSION} running on ${HOST}:${PORT}`
        );

        console.log(
            `👤 Login: admin / admin`
        );

        console.log(
            `🛣️ Multi-path: 3 XHTTP + 3 WebSocket per user`
        );

        console.log(
            `📡 Subscription: 6 configs + 2 branding entries`
        );

        console.log(
            `💙 POWERED BY YASIN BEHZAD`
        );

        console.log(
            `⚔️ Railway TCP Proxy NOT required`
        );
    }
);

async function shutdown(
    signal
) {

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
    () =>
        shutdown("SIGTERM")
);

process.on(
    "SIGINT",
    () =>
        shutdown("SIGINT")
);
