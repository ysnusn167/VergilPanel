import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import { spawn, spawnSync } from "node:child_process";
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

const VERSION = "0.10.0";

let xrayProcess = null;
let stoppingXray = false;
let xrayRestarting = false;
let xrayRestartPending = false;
let lastXrayExit = "none";

const sessions = new Map();

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

let lastSyncKey = "";

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

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`);

function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(String(password), salt, 64);

    return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}

function verifyPassword(password, stored) {
    const value = String(stored || "");

    if (value.startsWith("scrypt$")) {
        const [, saltHex, hashHex] = value.split("$");
        const expected = Buffer.from(hashHex || "", "hex");

        if (!saltHex || expected.length === 0) return false;

        const actual = crypto.scryptSync(
            String(password),
            Buffer.from(saltHex, "hex"),
            expected.length
        );

        return crypto.timingSafeEqual(actual, expected);
    }

    // Legacy unsalted SHA-256 hashes (upgraded automatically on login)
    const legacy = crypto
        .createHash("sha256")
        .update(String(password))
        .digest();

    const old = Buffer.from(value, "hex");

    return old.length === legacy.length &&
        crypto.timingSafeEqual(legacy, old);
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

    const session = sessions.get(cookies.vergil_session);

    if (!session) {
        return null;
    }

    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
        sessions.delete(cookies.vergil_session);
        return null;
    }

    return session;
}

/*
 * Login brute-force protection:
 * 8 failed attempts per IP in 5 minutes -> blocked until the window ends.
 * The LAST x-forwarded-for entry is the one added by Railway's edge,
 * so a client cannot spoof it by sending its own header.
 */

const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 5 * 60 * 1000;
const LOGIN_MAX_FAILS = 8;

function clientIp(req) {
    const fwd = String(req.headers["x-forwarded-for"] || "");
    const parts = fwd.split(",").map(x => x.trim()).filter(Boolean);

    return parts.length
        ? parts[parts.length - 1]
        : (req.socket.remoteAddress || "unknown");
}

function loginBlocked(ip) {
    const entry = loginAttempts.get(ip);

    if (!entry) return false;

    if (entry.reset < Date.now()) {
        loginAttempts.delete(ip);
        return false;
    }

    return entry.count >= LOGIN_MAX_FAILS;
}

function loginFail(ip) {
    const now = Date.now();
    let entry = loginAttempts.get(ip);

    if (!entry || entry.reset < now) {
        entry = { count: 0, reset: now + LOGIN_WINDOW_MS };
        loginAttempts.set(ip, entry);
    }

    entry.count += 1;
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

/* ---------- App settings (key/value) ---------- */

function getSetting(key, fallback = "") {
    const row = db
        .prepare("SELECT value FROM app_settings WHERE key = ?")
        .get(key);

    return row ? row.value : fallback;
}

function setSetting(key, value) {
    db.prepare(`
        INSERT INTO app_settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(key, String(value));
}

const RAW_PROTOCOLS = ["none", "shadowsocks", "reality"];
const SS_METHOD = "2022-blake3-aes-128-gcm";

function rawConfig() {
    const protocol = getSetting("raw_protocol", "none");

    return {
        host: getSetting("public_host", ""),
        port: getSetting("public_port", ""),
        protocol: RAW_PROTOCOLS.includes(protocol) ? protocol : "none",
        internalPort: Number(getSetting("raw_internal_port", "8443")) || 8443,
        sni: getSetting("reality_sni", "www.microsoft.com"),
        ssPsk: getSetting("ss_psk", ""),
        realityPrivate: getSetting("reality_private", ""),
        realityPublic: getSetting("reality_public", ""),
        realityShortId: getSetting("reality_short_id", "")
    };
}

function ensureRawSecrets() {
    if (!getSetting("ss_psk")) {
        setSetting("ss_psk", crypto.randomBytes(16).toString("base64"));
    }

    if (!getSetting("reality_short_id")) {
        setSetting("reality_short_id", crypto.randomBytes(4).toString("hex"));
    }

    if (!getSetting("reality_private") || !getSetting("reality_public")) {
        try {
            const result = spawnSync(XRAY_BIN, ["x25519"], {
                encoding: "utf8",
                timeout: 10000
            });

            const out = String(result.stdout || "");

            const priv = out.match(/private\s*key\s*:\s*(\S+)/i)?.[1];
            const pub = out.match(/(?:public\s*key|password)[^:\n]*:\s*(\S+)/i)?.[1];

            if (priv && pub) {
                setSetting("reality_private", priv);
                setSetting("reality_public", pub);
            } else {
                console.error("❌ Could not parse xray x25519 output");
            }
        } catch (error) {
            console.error("❌ Reality key generation failed:", error?.message);
        }
    }
}

function rawSignature() {
    const cfg = rawConfig();

    return JSON.stringify([
        cfg.protocol,
        cfg.internalPort,
        cfg.sni,
        cfg.ssPsk,
        cfg.realityPrivate,
        cfg.realityShortId
    ]);
}

function ssUserKey(user, psk) {
    return crypto
        .createHmac("sha256", psk)
        .update(user.uuid)
        .digest()
        .subarray(0, 16)
        .toString("base64");
}

function rawInbound(users) {
    const cfg = rawConfig();

    if (cfg.protocol === "none") return null;

    if (users.length === 0) {
        console.log("ℹ️ Raw TCP inbound skipped: no active users");
        return null;
    }

    ensureRawSecrets();

    const fresh = rawConfig();

    if (fresh.protocol === "shadowsocks") {
        return {
            listen: "0.0.0.0",
            port: fresh.internalPort,
            protocol: "shadowsocks",

            settings: {
                method: SS_METHOD,
                password: fresh.ssPsk,
                network: "tcp",
                clients: users.map(user => ({
                    password: ssUserKey(user, fresh.ssPsk),
                    email: user.username
                }))
            }
        };
    }

    if (fresh.protocol === "reality") {
        if (!fresh.realityPrivate || !fresh.realityPublic) {
            console.error("❌ Reality keys missing, raw inbound skipped");
            return null;
        }

        return {
            listen: "0.0.0.0",
            port: fresh.internalPort,
            protocol: "vless",

            settings: {
                decryption: "none",
                clients: users.map(user => ({
                    id: user.uuid,
                    email: user.username,
                    flow: "xtls-rprx-vision"
                }))
            },

            streamSettings: {
                network: "tcp",
                security: "reality",

                realitySettings: {
                    show: false,
                    dest: `${fresh.sni}:443`,
                    xver: 0,
                    serverNames: [fresh.sni],
                    privateKey: fresh.realityPrivate,
                    shortIds: [fresh.realityShortId]
                }
            }
        };
    }

    return null;
}

function rawLabel(protocol) {
    return protocol === "shadowsocks"
        ? "Shadowsocks (TCP)"
        : "VLESS + Reality (TCP)";
}

function makeRawLink(user) {
    const cfg = rawConfig();

    if (cfg.protocol === "none" || !cfg.host || !cfg.port) return null;

    const name = encodeURIComponent(user.username);

    if (cfg.protocol === "shadowsocks") {
        if (!cfg.ssPsk) return null;

        const userinfo = [
            SS_METHOD,
            cfg.ssPsk,
            ssUserKey(user, cfg.ssPsk)
        ].map(encodeURIComponent).join(":");

        return `ss://${userinfo}@${cfg.host}:${cfg.port}#${name}-SS`;
    }

    if (cfg.protocol === "reality") {
        if (!cfg.realityPublic) return null;

        const params = new URLSearchParams({
            encryption: "none",
            flow: "xtls-rprx-vision",
            security: "reality",
            sni: cfg.sni,
            fp: "chrome",
            pbk: cfg.realityPublic,
            sid: cfg.realityShortId,
            type: "tcp"
        });

        return `vless://${user.uuid}@${cfg.host}:${cfg.port}?${params.toString()}#${name}-REALITY`;
    }

    return null;
}

function rawLinkList(user) {
    const link = makeRawLink(user);

    return link ? [link] : [];
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

function activeKey() {
    return activeUsers()
        .map(user => user.uuid)
        .sort()
        .join(",") + "|" + rawSignature();
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

function generateBaseXrayConfig() {
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

function generateXrayConfig() {
    const config = generateBaseXrayConfig();
    const inbound = rawInbound(activeUsers());

    if (inbound) config.inbounds.push(inbound);

    return config;
}

async function writeXrayConfig() {
    const config = generateXrayConfig();

    lastSyncKey = activeKey();

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

    try {
        const test = spawnSync(
            XRAY_BIN,
            ["run", "-test", "-config", XRAY_CONFIG],
            { encoding: "utf8", timeout: 10000 }
        );

        console.log(`🧪 Xray config test: exit=${test.status}`);

        const out = `${test.stdout || ""}${test.stderr || ""}`.trim();

        if (out) {
            console.log(`[XRAY-TEST] ${out.slice(-1500)}`);
        }
    } catch (error) {
        console.error("🧪 Xray config test failed to run:", error);
    }

    const child = xrayProcess = spawn(
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
        console.error(
            "❌ Xray process error:",
            error
        );
    });

    xrayProcess.on("exit", (code, signal) => {
        console.log(
            `⚠️ Xray exited. code=${code} signal=${signal}`
        );

        lastXrayExit = `code=${code} signal=${signal}`;

        const wasCurrent = xrayProcess === child;

        if (wasCurrent) {
            xrayProcess = null;
        }

        if (
            wasCurrent &&
            !stoppingXray &&
            !xrayRestarting
        ) {
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
        // A restart is already running: ask for one more round afterwards
        // so the newest database state is always applied.
        xrayRestartPending = true;
        return;
    }

    xrayRestarting = true;

    try {
        do {
            xrayRestartPending = false;
            await stopXray();
            await startXray();
        } while (xrayRestartPending);
    } finally {
        xrayRestarting = false;
    }
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
            sni: domain,
            mode: "auto"
        });

    const wsParams =
        new URLSearchParams({
            encryption: "none",
            security: "tls",
            type: "ws",
            path: WS_PATH,
            host: domain,
            sni: domain
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
 * این کانفیگ عمداً کار نمی‌کند.
 * فقط برای نمایش پیام مالک/برند داخل Subscription است.
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
            "ساخته شده توسط یاسین - کاملا رایگان و غیرقابل فروش"
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
            ...rawLinkList(user),
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

function loginPage(error = "") {
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

`).join("")
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

    const raw = rawConfig();

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

<div class="card form">

<h1>
🛰️ شبکه و پروتکل TCP
</h1>

<p class="muted">
برای کانفیگ‌های TCP (Shadowsocks یا Reality) در Railway یک TCP Proxy بسازید.
پورت داخلی (Application Port) را برابر مقدار «پورت داخلی» پایین بگذارید،
سپس دامنه و پورتی که Railway می‌دهد را در Host و Port بنویسید.
</p>

<form
    method="POST"
    action="/settings/network"
>

<label>
Host (دامنه TCP Proxy یا دامنه اختصاصی)
</label>

<input
    name="public_host"
    value="${escapeHtml(raw.host)}"
    placeholder="example.proxy.rlwy.net"
    maxlength="253"
    dir="ltr"
>

<label>
Port (پورت بیرونی که Railway می‌دهد)
</label>

<input
    name="public_port"
    value="${escapeHtml(raw.port)}"
    placeholder="12345"
    inputmode="numeric"
    maxlength="5"
    dir="ltr"
>

<label>
پروتکل TCP
</label>

<select
    name="raw_protocol"
    dir="ltr"
>
<option value="none" ${raw.protocol === "none" ? "selected" : ""}>غیرفعال</option>
<option value="shadowsocks" ${raw.protocol === "shadowsocks" ? "selected" : ""}>Shadowsocks 2022</option>
<option value="reality" ${raw.protocol === "reality" ? "selected" : ""}>VLESS + Reality</option>
</select>

<label>
پورت داخلی (Application Port در TCP Proxy)
</label>

<input
    name="raw_internal_port"
    value="${escapeHtml(String(raw.internalPort))}"
    inputmode="numeric"
    maxlength="5"
    dir="ltr"
>

<label>
دامنه ظاهری Reality (فقط برای Reality)
</label>

<input
    name="reality_sni"
    value="${escapeHtml(raw.sni)}"
    maxlength="253"
    dir="ltr"
>

<br><br>

<button
    class="btn primary"
    type="submit"
>
💾 ذخیره تنظیمات شبکه
</button>

</form>

<br>

<div class="notice">

⚠️ با فعال کردن این بخش، Xray مستقیماً روی اینترنت باز می‌شود.
فقط یک TCP Proxy برای هر سرویس مجاز است، پس هم‌زمان فقط یک پروتکل TCP فعال است.

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

    const rawLink = makeRawLink(user);
    const rawQr = rawLink ? await qrCode(rawLink) : "";
    const rawSection = rawLink
        ? `
<br><br>

<h2>
🛰️ ${rawLabel(rawConfig().protocol)}
</h2>

<p class="muted small">
این کانفیگ روی پورت TCP Proxy است و فقط روی اینترنت‌هایی کار می‌کند که پورت غیر ۴۴۳ را باز می‌گذارند.
</p>

<pre class="config">${escapeHtml(rawLink)}</pre>

<button
    class="btn"
    onclick='copyText(${JSON.stringify(rawLink)})'
>
📋 Copy
</button>

<br><br>

<img
    src="${rawQr}"
    alt="TCP QR"
    style="max-width:260px"
>
`
        : "";

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
⚔️ ${escapeHtml(user.username)}
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

${rawSection}

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
 * Default Admin
 *
 * Fresh deployment:
 *
 * admin / admin
 *
 * Railway Variables can override it.
 */

function ensureDefaultAdmin() {
    const envUser = String(process.env.ADMIN_USERNAME || "").trim();
    const envPass = String(process.env.ADMIN_PASSWORD || "");

    const count = db
        .prepare("SELECT COUNT(*) AS c FROM admins")
        .get().c;

    // Explicit credentials from Railway Variables (also a recovery path)
    if (envPass) {
        const target = envUser
            ? db.prepare("SELECT * FROM admins WHERE username = ?").get(envUser)
            : getAdmin();

        if (target) {
            db.prepare("UPDATE admins SET password_hash = ? WHERE id = ?")
                .run(hashPassword(envPass), target.id);

            console.log(`👤 Admin ready: ${target.username}`);
        } else {
            const username = envUser || "admin";

            db.prepare(`
                INSERT INTO admins(username, password_hash, created_at)
                VALUES (?, ?, ?)
            `).run(username, hashPassword(envPass), nowIso());

            console.log(`👤 Admin created: ${username}`);
        }

        return;
    }

    // Fresh install without variables: default login admin / admin
    // (created ONLY when no admin exists; never reset on restart)
    if (count === 0) {
        const username = envUser || "admin";
        const password = "admin";

        db.prepare(`
            INSERT INTO admins(username, password_hash, created_at)
            VALUES (?, ?, ?)
        `).run(username, hashPassword(password), nowIso());

        console.log("==================================================");
        console.log("👤 Default admin created");
        console.log(`   Username: ${username}`);
        console.log(`   Password: ${password}`);
        console.log("   Change it in Settings right after the first login.");
        console.log("==================================================");

        return;
    }

    console.log("👤 Admin accounts loaded");
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

    if (!verifyPassword(password, admin.password_hash)) {
        return false;
    }

    if (!String(admin.password_hash).startsWith("scrypt$")) {
        db.prepare("UPDATE admins SET password_hash = ? WHERE id = ?")
            .run(hashPassword(password), admin.id);
    }

    return true;
}

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

    if (!/^[A-Za-z0-9_-]{1,32}$/.test(username)) {
        throw new Error(
            "نام کاربری فقط می‌تواند شامل حروف انگلیسی، عدد، _ و - باشد (حداکثر ۳۲ کاراکتر)."
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
            "این نام کاربری قبلاً وجود دارد."
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

                upstream.on("error", () => res.destroy());

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

            res.end("Bad Gateway");
        }
    );

    res.on("close", () => {
        if (!res.writableEnded) {
            proxy.destroy();
        }
    });

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

    for (const sock of [upstream, clientSocket]) {
        sock.setNoDelay(true);
        sock.setKeepAlive(true, 30000);
    }

    upstream.on("close", () => {
        try {
            clientSocket.destroy();
        } catch {}
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

            clientSocket.pipe(upstream);
            upstream.pipe(clientSocket);
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

            "Profile-Update-Interval": "6",

            ...(user.expires_at
                ? {
                    "Subscription-Userinfo":
                        `upload=0; download=0; total=0; expire=${Math.floor(new Date(user.expires_at).getTime() / 1000)}`
                }
                : {}),

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

            sendJson(
                res,
                {
                    ok: true,
                    panel: VERSION,

                    lastXrayExit,

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

            const ip = clientIp(req);

            if (loginBlocked(ip)) {
                sendHtml(
                    res,
                    loginPage(
                        "تلاش‌های ناموفق زیاد بود. چند دقیقه بعد دوباره امتحان کنید."
                    ),
                    429
                );

                return;
            }

            const authOk = authenticate(username, password);

            if (!authOk) {
                loginFail(ip);
            } else {
                loginAttempts.delete(ip);
            }

            if (!authOk) {

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


            res.writeHead(
                302,
                {
                    Location:
                        (username === "admin" && password === "admin")
                            ? "/settings"
                            : "/dashboard",

                    "Set-Cookie":
                        `vergil_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=${SESSION_TTL_MS / 1000}`
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

        if (
            pathname === "/settings/network" &&
            req.method === "POST"
        ) {

            try {

                const form =
                    await readForm(req);

                const hostRe =
                    /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/;

                const host =
                    String(form.get("public_host") || "")
                        .trim()
                        .toLowerCase();

                const publicPort =
                    String(form.get("public_port") || "").trim();

                const protocol =
                    String(form.get("raw_protocol") || "none");

                const internalPort =
                    Number(String(form.get("raw_internal_port") || "8443").trim());

                const sni =
                    String(form.get("reality_sni") || "www.microsoft.com")
                        .trim()
                        .toLowerCase();

                if (host && !hostRe.test(host)) {
                    throw new Error(
                        "Host معتبر نیست (فقط دامنه یا IP، بدون http و بدون پورت)."
                    );
                }

                if (
                    publicPort &&
                    !(/^\d{1,5}$/.test(publicPort) &&
                        Number(publicPort) >= 1 &&
                        Number(publicPort) <= 65535)
                ) {
                    throw new Error("Port بیرونی معتبر نیست.");
                }

                if (!RAW_PROTOCOLS.includes(protocol)) {
                    throw new Error("پروتکل نامعتبر است.");
                }

                if (
                    !Number.isInteger(internalPort) ||
                    internalPort < 1 ||
                    internalPort > 65535
                ) {
                    throw new Error("پورت داخلی معتبر نیست.");
                }

                if (
                    [PORT, XRAY_XHTTP_PORT, XRAY_WS_PORT].includes(internalPort)
                ) {
                    throw new Error(
                        "این پورت داخلی قبلاً توسط پنل استفاده می‌شود؛ پورت دیگری مثل 8443 انتخاب کنید."
                    );
                }

                if (!hostRe.test(sni)) {
                    throw new Error("دامنه Reality معتبر نیست.");
                }

                setSetting("public_host", host);
                setSetting("public_port", publicPort);
                setSetting("raw_protocol", protocol);
                setSetting("raw_internal_port", internalPort);
                setSetting("reality_sni", sni);

                if (protocol !== "none") {
                    ensureRawSecrets();
                }

                if (
                    protocol === "reality" &&
                    !getSetting("reality_public")
                ) {
                    throw new Error(
                        "ساخت کلید Reality ناموفق بود؛ لاگ‌های Railway را بررسی کنید."
                    );
                }

                restartXray().catch(error => {
                    console.error("❌ Xray restart failed:", error);
                });

                sendHtml(
                    res,
                    settingsPage(
                        req,
                        "تنظیمات شبکه ذخیره شد و Xray دوباره راه‌اندازی می‌شود."
                    )
                );

            } catch (error) {

                sendHtml(
                    res,
                    settingsPage(
                        req,
                        "",
                        error?.message ||
                            "خطا در ذخیره تنظیمات شبکه."
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

// Node kills requests lasting more than 5 minutes by default,
// which would drop long XHTTP uploads. Disable that limit.
server.requestTimeout = 0;
server.headersTimeout = 80_000;
server.keepAliveTimeout = 75_000;

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

// Remove expired users from Xray without waiting for the next manual change
setInterval(() => {
    try {
        if (!xrayRestarting && activeKey() !== lastSyncKey) {
            restartXray().catch(error => {
                console.error("❌ Scheduled sync failed:", error);
            });
        }
    } catch (error) {
        console.error("❌ Sync check failed:", error);
    }
}, 30_000);

setInterval(() => {
    const now = Date.now();

    for (const [token, session] of sessions) {
        if (now - session.createdAt > SESSION_TTL_MS) {
            sessions.delete(token);
        }
    }

    for (const [ip, entry] of loginAttempts) {
        if (entry.reset < now) {
            loginAttempts.delete(ip);
        }
    }
}, 10 * 60 * 1000);

server.listen(
    PORT,
    HOST,
    () => {

        console.log(
            `⚔️ VergilPanel v${VERSION} running on ${HOST}:${PORT}`
        );

        console.log(
            `🔐 Fresh install login: admin / admin (change it in Settings)`
        );

        console.log(
            `💙 POWERED BY YASIN BEHZAD`
        );

        console.log(
            `⚔️ Railway TCP Proxy is optional (Settings → Network)`
        );
    }
);

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
