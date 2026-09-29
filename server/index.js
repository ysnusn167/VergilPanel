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

/*
 * Internal Xray ports.
 *
 * XHTTP is proxied by normal HTTP.
 * Each WebSocket protocol gets its own internal port.
 * Shadowsocks uses a raw TCP port.
 */

const XRAY_XHTTP_PORT =
    Number(process.env.XRAY_XHTTP_PORT || 10001);

const XRAY_VLESS_WS_PORT =
    Number(process.env.XRAY_VLESS_WS_PORT || 10002);

const XRAY_VMESS_WS_PORT =
    Number(process.env.XRAY_VMESS_WS_PORT || 10003);

const XRAY_TROJAN_WS_PORT =
    Number(process.env.XRAY_TROJAN_WS_PORT || 10004);

const XRAY_SS_PORT =
    Number(
        process.env.XRAY_SS_PORT ||
        process.env.RAILWAY_TCP_APPLICATION_PORT ||
        10005
    );

const XHTTP_PATH =
    process.env.XHTTP_PATH || "/xhttp";

const VLESS_WS_PATH =
    process.env.VLESS_WS_PATH || "/ws";

const VMESS_WS_PATH =
    process.env.VMESS_WS_PATH || "/vmess";

const TROJAN_WS_PATH =
    process.env.TROJAN_WS_PATH || "/trojan";

const VERSION = "1.0.0";

const BRAND_1 =
    "ساخته شده توسط یاسین - پنل کاملا رایگان و غیرقابل فروش";

const BRAND_2 =
    "به یاد زنده یاد علی نور 🖤";

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


// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

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

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function parseCookies(req) {
    const result = {};

    const cookie = req.headers.cookie;

    if (!cookie) {
        return result;
    }

    for (const item of cookie.split(";")) {
        const index = item.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key = item.slice(0, index).trim();
        const value = item.slice(index + 1).trim();

        result[key] = decodeURIComponent(value);
    }

    return result;
}

function getSession(req) {
    const cookies = parseCookies(req);

    if (!cookies.session) {
        return null;
    }

    return sessions.get(cookies.session) || null;
}

function redirect(res, location) {
    res.writeHead(302, {
        Location: location
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

function readBody(req) {
    return new Promise((resolve, reject) => {
        let body = "";

        req.on("data", chunk => {
            body += chunk.toString();

            if (body.length > 5_000_000) {
                req.destroy();
                reject(new Error("Request body too large"));
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

function requireAuth(req, res) {
    const session = getSession(req);

    if (!session) {
        redirect(res, "/login");
        return null;
    }

    return session;
}

function getPublicHost(req) {
    const forwardedHost =
        req.headers["x-forwarded-host"] ||
        req.headers.host;

    if (forwardedHost) {
        return String(forwardedHost).split(",")[0].trim();
    }

    return "localhost";
}

function getPublicOrigin(req) {
    const proto =
        req.headers["x-forwarded-proto"] ||
        "https";

    return `${proto}://${getPublicHost(req)}`;
}

function activeUsers() {
    return db.prepare(`
        SELECT *
        FROM users
        WHERE status = 'active'
        ORDER BY id DESC
    `).all();
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

function normalizeProtocol(protocol) {
    const value = String(protocol || "vless").toLowerCase();

    if (
        value === "vless" ||
        value === "vmess" ||
        value === "trojan" ||
        value === "shadowsocks"
    ) {
        return value;
    }

    return "vless";
}

function protocolLabel(protocol) {
    switch (normalizeProtocol(protocol)) {
        case "vless":
            return "VLESS";
        case "vmess":
            return "VMess";
        case "trojan":
            return "Trojan";
        case "shadowsocks":
            return "Shadowsocks";
        default:
            return "VLESS";
    }
}

function protocolColor(protocol) {
    switch (normalizeProtocol(protocol)) {
        case "vless":
            return "#38bdf8";

        case "vmess":
            return "#a78bfa";

        case "trojan":
            return "#f472b6";

        case "shadowsocks":
            return "#34d399";

        default:
            return "#38bdf8";
    }
}


// ------------------------------------------------------------
// Default admin
// ------------------------------------------------------------

function ensureDefaultAdmin() {
    const existing = getAdmin();

    if (existing) {
        return;
    }

    const username =
        process.env.ADMIN_USERNAME || "admin";

    const password =
        process.env.ADMIN_PASSWORD || "admin";

    db.prepare(`
        INSERT INTO admins
        (username, password_hash, created_at)
        VALUES (?, ?, ?)
    `).run(
        username,
        hashPassword(password),
        nowIso()
    );

    console.log(`👤 Default admin created: ${username}`);
}


// ------------------------------------------------------------
// Xray configuration
// ------------------------------------------------------------

function generateXrayConfig() {
    const users = activeUsers();

    const vlessClients = users
        .filter(user => normalizeProtocol(user.protocol) === "vless")
        .map(user => ({
            id: user.uuid,
            email: user.username
        }));

    const vmessClients = users
        .filter(user => normalizeProtocol(user.protocol) === "vmess")
        .map(user => ({
            id: user.uuid,
            email: user.username,
            alterId: 0
        }));

    const trojanClients = users
        .filter(user => normalizeProtocol(user.protocol) === "trojan")
        .map(user => ({
            password: user.uuid,
            email: user.username
        }));

    /*
     * Shadowsocks uses a generated password based on the UUID.
     * This keeps every user isolated.
     */
    const shadowsocksClients = users
        .filter(user => normalizeProtocol(user.protocol) === "shadowsocks");

    const inbounds = [];


    // --------------------------------------------------------
    // VLESS XHTTP
    // --------------------------------------------------------

    if (vlessClients.length > 0) {
        inbounds.push({
            listen: "127.0.0.1",
            port: XRAY_XHTTP_PORT,
            protocol: "vless",

            settings: {
                clients: vlessClients,
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
        });
    }


    // --------------------------------------------------------
    // VLESS WebSocket
    // --------------------------------------------------------

    if (vlessClients.length > 0) {
        inbounds.push({
            listen: "127.0.0.1",
            port: XRAY_VLESS_WS_PORT,
            protocol: "vless",

            settings: {
                clients: vlessClients,
                decryption: "none"
            },

            streamSettings: {
                network: "websocket",
                security: "none",

                wsSettings: {
                    path: VLESS_WS_PATH
                }
            }
        });
    }


    // --------------------------------------------------------
    // VMess WebSocket
    // --------------------------------------------------------

    if (vmessClients.length > 0) {
        inbounds.push({
            listen: "127.0.0.1",
            port: XRAY_VMESS_WS_PORT,
            protocol: "vmess",

            settings: {
                clients: vmessClients
            },

            streamSettings: {
                network: "websocket",
                security: "none",

                wsSettings: {
                    path: VMESS_WS_PATH
                }
            }
        });
    }


    // --------------------------------------------------------
    // Trojan WebSocket
    // --------------------------------------------------------

    if (trojanClients.length > 0) {
        inbounds.push({
            listen: "127.0.0.1",
            port: XRAY_TROJAN_WS_PORT,
            protocol: "trojan",

            settings: {
                clients: trojanClients
            },

            streamSettings: {
                network: "websocket",
                security: "none",

                wsSettings: {
                    path: TROJAN_WS_PATH
                }
            }
        });
    }


    // --------------------------------------------------------
    // Shadowsocks TCP
    // --------------------------------------------------------

    if (shadowsocksClients.length > 0) {
        inbounds.push({
            listen: "0.0.0.0",
            port: XRAY_SS_PORT,
            protocol: "shadowsocks",

            settings: {
                method: "chacha20-ietf-poly1305",
                password: shadowsocksClients[0].uuid,
                network: "tcp,udp"
            }
        });
    }


    return {
        log: {
            loglevel: "warning"
        },

        inbounds,

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

        stoppingXray = true;

        const processToStop = xrayProcess;
        xrayProcess = null;

        try {
            processToStop.kill("SIGTERM");
        } catch {}

        setTimeout(() => {
            try {
                processToStop.kill("SIGKILL");
            } catch {}

            stoppingXray = false;
            resolve();
        }, 2000);
    });
}

async function startXray() {
    await writeXrayConfig();

    if (xrayProcess) {
        return;
    }

    stoppingXray = false;

    console.log(`⚙️ Xray binary: ${XRAY_BIN}`);

    const child = spawn(
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

    xrayProcess = child;

    child.stdout.on("data", data => {
        process.stdout.write(`[XRAY] ${data}`);
    });

    child.stderr.on("data", data => {
        process.stderr.write(`[XRAY] ${data}`);
    });

    child.on("error", error => {
        console.error(
            "❌ Xray process error:",
            error
        );

        xrayProcess = null;
    });

    child.on("exit", async (code, signal) => {
        console.log(
            `⚠️ Xray exited. code=${code} signal=${signal}`
        );

        xrayProcess = null;

        if (
            !stoppingXray &&
            !xrayRestarting
        ) {
            xrayRestarting = true;

            setTimeout(async () => {
                try {
                    await startXray();
                } catch (error) {
                    console.error(
                        "❌ Xray restart failed:",
                        error
                    );
                } finally {
                    xrayRestarting = false;
                }
            }, 1500);
        }
    });
}

async function restartXray() {
    await stopXray();
    await startXray();
}


// ------------------------------------------------------------
// Links
// ------------------------------------------------------------

function makeVlessLinks(user, origin) {
    const domain =
        new URL(origin).hostname;

    const xhttpParams =
        new URLSearchParams({
            encryption: "none",
            security: "none",
            type: "xhttp",
            path: XHTTP_PATH,
            host: domain,
            mode: "auto"
        });

    const wsParams =
        new URLSearchParams({
            encryption: "none",
            security: "none",
            type: "ws",
            path: VLESS_WS_PATH,
            host: domain
        });

    return {
        xhttp:
            `vless://${user.uuid}@${domain}:443?${xhttpParams.toString()}#${encodeURIComponent(
                `${user.username}-VLESS-XHTTP`
            )}`,

        websocket:
            `vless://${user.uuid}@${domain}:443?${wsParams.toString()}#${encodeURIComponent(
                `${user.username}-VLESS-WS`
            )}`
    };
}

function makeVmessLink(user, origin) {
    const domain =
        new URL(origin).hostname;

    const config = {
        v: "2",
        ps: `${user.username}-VMess`,
        add: domain,
        port: "443",
        id: user.uuid,
        aid: "0",
        scy: "auto",
        net: "ws",
        type: "none",
        host: domain,
        path: VMESS_WS_PATH,
        tls: ""
    };

    return `vmess://${Buffer
        .from(JSON.stringify(config), "utf8")
        .toString("base64")}`;
}

function makeTrojanLink(user, origin) {
    const domain =
        new URL(origin).hostname;

    const params =
        new URLSearchParams({
            type: "ws",
            security: "none",
            path: TROJAN_WS_PATH,
            host: domain
        });

    return (
        `trojan://${encodeURIComponent(user.uuid)}` +
        `@${domain}:443?${params.toString()}` +
        `#${encodeURIComponent(`${user.username}-Trojan`)}`
    );
}

function getTcpHost() {
    return (
        process.env.RAILWAY_TCP_PROXY_DOMAIN ||
        process.env.TCP_PROXY_DOMAIN ||
        ""
    );
}

function getTcpPort() {
    return Number(
        process.env.RAILWAY_TCP_PROXY_PORT ||
        process.env.TCP_PROXY_PORT ||
        0
    );
}

function makeShadowsocksLink(user) {
    const host =
        getTcpHost();

    const port =
        getTcpPort();

    /*
     * Railway exposes the raw TCP service using:
     *
     * RAILWAY_TCP_PROXY_DOMAIN
     * RAILWAY_TCP_PROXY_PORT
     */

    if (!host || !port) {
        return (
            `ss://INVALID_TCP_PROXY#${encodeURIComponent(
                `${user.username}-Shadowsocks-SET-TCP-PROXY`
            )}`
        );
    }

    const method =
        "chacha20-ietf-poly1305";

    const userInfo =
        Buffer
            .from(
                `${method}:${user.uuid}`,
                "utf8"
            )
            .toString("base64url");

    return (
        `ss://${userInfo}@${host}:${port}` +
        `#${encodeURIComponent(`${user.username}-Shadowsocks`)}`
    );
}


// ------------------------------------------------------------
// Subscription
// ------------------------------------------------------------

function makeDummyConfigs() {
    const dummy1 =
        `vless://00000000-0000-0000-0000-000000000000@0.0.0.0:443?type=tcp&security=none#${encodeURIComponent(
            BRAND_1
        )}`;

    const dummy2 =
        `vless://11111111-1111-1111-1111-111111111111@0.0.0.0:443?type=tcp&security=none#${encodeURIComponent(
            BRAND_2
        )}`;

    return [
        dummy1,
        dummy2
    ];
}

function makeSubscription(user, origin) {
    const links = [];

    const protocol =
        normalizeProtocol(user.protocol);

    if (protocol === "vless") {
        const vless =
            makeVlessLinks(
                user,
                origin
            );

        links.push(vless.xhttp);
        links.push(vless.websocket);
    }

    if (protocol === "vmess") {
        links.push(
            makeVmessLink(
                user,
                origin
            )
        );
    }

    if (protocol === "trojan") {
        links.push(
            makeTrojanLink(
                user,
                origin
            )
        );
    }

    if (protocol === "shadowsocks") {
        links.push(
            makeShadowsocksLink(user)
        );
    }

    links.push(
        ...makeDummyConfigs()
    );

    return Buffer
        .from(
            links.join("\n"),
            "utf8"
        )
        .toString("base64");
}


// ------------------------------------------------------------
// User creation
// ------------------------------------------------------------

function createUser(form) {
    const username =
        String(form.get("username") || "")
            .trim();

    const protocol =
        normalizeProtocol(
            form.get("protocol")
        );

    const trafficLimitGB =
        Number(
            form.get("traffic_limit") || 0
        );

    const expiresAt =
        String(
            form.get("expires_at") || ""
        ).trim();

    if (!username) {
        throw new Error(
            "Username is required"
        );
    }

    if (
        !/^[a-zA-Z0-9_.-]{2,32}$/.test(
            username
        )
    ) {
        throw new Error(
            "Username must be 2-32 characters and contain only letters, numbers, _, -, ."
        );
    }

    const existing =
        db.prepare(`
            SELECT id
            FROM users
            WHERE username = ?
        `).get(username);

    if (existing) {
        throw new Error(
            "Username already exists"
        );
    }

    const uuid =
        crypto.randomUUID();

    const subscriptionToken =
        randomToken(32);

    const trafficLimitBytes =
        Math.max(
            0,
            trafficLimitGB
        ) *
        1024 *
        1024 *
        1024;

    const result =
        db.prepare(`
            INSERT INTO users
            (
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
            VALUES (?, ?, ?, ?, 0, ?, 'active', ?, ?)
        `).run(
            username,
            uuid,
            protocol,
            trafficLimitBytes,
            expiresAt || null,
            subscriptionToken,
            nowIso()
        );

    console.log(
        `👤 User created: ${username} (${protocol})`
    );

    return db.prepare(`
        SELECT *
        FROM users
        WHERE id = ?
    `).get(result.lastInsertRowid);
}


// ------------------------------------------------------------
// HTTP proxy
// ------------------------------------------------------------

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
            host: `127.0.0.1:${targetPort}`
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
                            "text/plain; charset=utf-8"
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


// ------------------------------------------------------------
// WebSocket proxy
// ------------------------------------------------------------

function proxyWebSocket(
    req,
    clientSocket,
    head,
    targetPort
) {
    const upstream =
        net.connect({
            host: "127.0.0.1",
            port: targetPort
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
                if (Array.isArray(value)) {
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


// ------------------------------------------------------------
// Raw TCP proxy for Shadowsocks
// ------------------------------------------------------------

function proxyTcpToXray(
    clientSocket
) {
    const upstream =
        net.connect({
            host: "127.0.0.1",
            port: XRAY_SS_PORT
        });

    upstream.on(
        "connect",
        () => {
            clientSocket.pipe(upstream);
            upstream.pipe(clientSocket);
        }
    );

    upstream.on(
        "error",
        error => {
            console.error(
                "TCP proxy error:",
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


// ------------------------------------------------------------
// Login page
// ------------------------------------------------------------

function loginPage(error = "") {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1.0">

<title>VergilPanel - Login</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    background:
        radial-gradient(
            circle at top,
            #102a46 0,
            #07111e 45%,
            #030812 100%
        );
    color: #e5f3ff;
    font-family:
        Arial,
        Helvetica,
        sans-serif;

    display: flex;
    align-items: center;
    justify-content: center;
}

.card {
    width: min(420px, 92%);
    padding: 35px;

    background:
        rgba(8, 21, 36, .92);

    border:
        1px solid rgba(56,189,248,.25);

    border-radius: 22px;

    box-shadow:
        0 25px 80px
        rgba(0,0,0,.55);
}

.logo {
    text-align: center;
    font-size: 34px;
    font-weight: 900;
    color: #38bdf8;
    margin-bottom: 5px;
}

.subtitle {
    text-align: center;
    color: #7fa2bb;
    margin-bottom: 30px;
}

label {
    display: block;
    margin-bottom: 8px;
    color: #9fc0d5;
}

input {
    width: 100%;
    padding: 13px 15px;

    border-radius: 12px;
    border:
        1px solid
        rgba(255,255,255,.1);

    background: #071321;
    color: white;

    outline: none;
    margin-bottom: 18px;
}

input:focus {
    border-color: #38bdf8;
}

button {
    width: 100%;
    border: 0;
    padding: 14px;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #0284c7,
            #38bdf8
        );

    color: white;
    font-weight: 800;
    cursor: pointer;
}

.error {
    background: rgba(239,68,68,.12);
    border: 1px solid rgba(239,68,68,.3);
    color: #fca5a5;
    padding: 12px;
    border-radius: 10px;
    margin-bottom: 18px;
}

.footer {
    text-align: center;
    margin-top: 25px;
    color: #57768c;
    font-size: 12px;
}

</style>
</head>

<body>

<div class="card">

    <div class="logo">
        ⚔️ VergilPanel
    </div>

    <div class="subtitle">
        V1.0.0
    </div>

    ${
        error
            ? `<div class="error">${escapeHtml(error)}</div>`
            : ""
    }

    <form method="POST"
          action="/login">

        <label>Username</label>

        <input
            name="username"
            autocomplete="username"
            required
        >

        <label>Password</label>

        <input
            type="password"
            name="password"
            autocomplete="current-password"
            required
        >

        <button type="submit">
            LOGIN
        </button>

    </form>

    <div class="footer">
        POWERED BY YASIN BEHZAD
    </div>

</div>

</body>
</html>
`;
}


// ------------------------------------------------------------
// Dashboard
// ------------------------------------------------------------

function dashboardPage(users, req) {
    const origin =
        getPublicOrigin(req);

    const rows =
        users.map(user => {
            const protocol =
                protocolLabel(
                    user.protocol
                );

            const color =
                protocolColor(
                    user.protocol
                );

            const expires =
                user.expires_at
                    ? new Date(
                        user.expires_at
                    ).toLocaleString()
                    : "Unlimited";

            const traffic =
                user.traffic_limit_bytes
                    ? `${(
                        user.traffic_limit_bytes /
                        1024 /
                        1024 /
                        1024
                    ).toFixed(2)} GB`
                    : "Unlimited";

            return `
<tr>

<td>
    <strong>
        ${escapeHtml(user.username)}
    </strong>

    <div class="muted">
        ${escapeHtml(user.uuid)}
    </div>
</td>

<td>
    <span
        class="protocol"
        style="--protocol:${color}">
        ${protocol}
    </span>
</td>

<td>
    ${traffic}
</td>

<td>
    ${escapeHtml(expires)}
</td>

<td>
    <span class="${
        user.status === "active"
            ? "active"
            : "disabled"
    }">
        ${escapeHtml(user.status)}
    </span>
</td>

<td>

<div class="actions">

<a
    class="btn small"
    href="/users/config?id=${user.id}">
    CONFIG
</a>

<form
    method="POST"
    action="/users/toggle"
    style="display:inline">

<input
    type="hidden"
    name="id"
    value="${user.id}">

<button
    class="btn small secondary"
    type="submit">
    ${
        user.status === "active"
            ? "DISABLE"
            : "ENABLE"
    }
</button>

</form>

<form
    method="POST"
    action="/users/delete"
    style="display:inline"
    onsubmit="return confirm('Delete this user?')">

<input
    type="hidden"
    name="id"
    value="${user.id}">

<button
    class="btn small danger"
    type="submit">
    DELETE
</button>

</form>

</div>

</td>

</tr>
`;
        })
        .join("");

    return `
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0">

<title>VergilPanel</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;

    background:
        radial-gradient(
            circle at top,
            #102b48,
            #06101d 50%,
            #03070e
        );

    color: #e8f5ff;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    min-height: 100vh;
}

nav {
    height: 70px;

    padding:
        0 25px;

    display: flex;
    align-items: center;
    justify-content: space-between;

    border-bottom:
        1px solid
        rgba(56,189,248,.12);

    background:
        rgba(3,10,20,.65);

    backdrop-filter: blur(12px);
}

.logo {
    color: #38bdf8;
    font-weight: 900;
    font-size: 22px;
}

.navlinks {
    display: flex;
    gap: 10px;
}

.navlinks a {
    color: #9fc0d5;
    text-decoration: none;
    padding: 8px 12px;
    border-radius: 8px;
}

.navlinks a:hover {
    background: rgba(56,189,248,.1);
    color: white;
}

.container {
    width: min(1250px, 94%);
    margin: 35px auto;
}

.hero {
    display: flex;
    justify-content: space-between;
    align-items: center;

    margin-bottom: 25px;
}

.hero h1 {
    margin: 0;
    font-size: 30px;
}

.hero p {
    color: #7897ad;
}

.btn {
    display: inline-block;

    border: 0;

    padding: 11px 16px;

    border-radius: 10px;

    background:
        linear-gradient(
            135deg,
            #0284c7,
            #38bdf8
        );

    color: white;

    font-weight: 800;

    text-decoration: none;

    cursor: pointer;
}

.small {
    padding: 7px 9px;
    font-size: 11px;
}

.secondary {
    background: #16283b;
}

.danger {
    background: #7f1d1d;
}

.card {
    background:
        rgba(7,20,34,.88);

    border:
        1px solid
        rgba(56,189,248,.12);

    border-radius: 18px;

    overflow: hidden;

    box-shadow:
        0 20px 60px
        rgba(0,0,0,.25);
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 17px;
    border-bottom:
        1px solid
        rgba(255,255,255,.05);
}

th {
    color: #7394aa;
    font-size: 12px;
    text-transform: uppercase;
}

.muted {
    color: #526f83;
    font-size: 11px;
    margin-top: 5px;
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
}

.protocol {
    display: inline-block;
    color: var(--protocol);
    border:
        1px solid
        color-mix(
            in srgb,
            var(--protocol) 30%,
            transparent
        );

    background:
        color-mix(
            in srgb,
            var(--protocol) 8%,
            transparent
        );

    padding:
        5px 9px;

    border-radius: 20px;
    font-size: 11px;
    font-weight: 800;
}

.active,
.disabled {
    padding: 5px 9px;
    border-radius: 20px;
    font-size: 11px;
}

.active {
    color: #34d399;
    background: rgba(52,211,153,.1);
}

.disabled {
    color: #fb7185;
    background: rgba(251,113,133,.1);
}

.actions {
    display: flex;
    gap: 5px;
    flex-wrap: wrap;
}

.empty {
    text-align: center;
    padding: 60px;
    color: #658197;
}

.brand {
    margin-top: 25px;
    text-align: center;
    color: #58758a;
    font-size: 12px;
}

</style>

</head>

<body>

<nav>

<div class="logo">
    ⚔️ VergilPanel
    <span style="font-size:12px;color:#647f94">
        v${VERSION}
    </span>
</div>

<div class="navlinks">

<a href="/">
    Dashboard
</a>

<a href="/users/new">
    + New User
</a>

<a href="/settings">
    Settings
</a>

<a href="/logout">
    Logout
</a>

</div>

</nav>

<div class="container">

<div class="hero">

<div>
    <h1>
        Users
    </h1>

    <p>
        Manage your VPN users and configurations.
    </p>
</div>

<a
    class="btn"
    href="/users/new">
    + CREATE USER
</a>

</div>

<div class="card">

${
    users.length
        ? `
<table>

<thead>

<tr>
<th>User</th>
<th>Protocol</th>
<th>Traffic</th>
<th>Expiration</th>
<th>Status</th>
<th>Actions</th>
</tr>

</thead>

<tbody>
${rows}
</tbody>

</table>
`
        : `
<div class="empty">
    No users yet.
</div>
`
}

</div>

<div class="brand">
    💙 ${escapeHtml(BRAND_1)}
    <br>
    🖤 ${escapeHtml(BRAND_2)}
    <br><br>
    POWERED BY YASIN BEHZAD
</div>

</div>

</body>

</html>
`;
}


// ------------------------------------------------------------
// New user page
// ------------------------------------------------------------

function newUserPage(error = "") {
    return `
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0">

<title>Create User - VergilPanel</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;

    min-height: 100vh;

    background:
        radial-gradient(
            circle at top,
            #102b48,
            #06101d 50%,
            #03070e
        );

    color: #e8f5ff;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}

nav {
    height: 70px;

    padding: 0 25px;

    display: flex;
    justify-content: space-between;
    align-items: center;

    background:
        rgba(3,10,20,.7);

    border-bottom:
        1px solid
        rgba(56,189,248,.12);
}

.logo {
    color: #38bdf8;
    font-weight: 900;
    font-size: 22px;
}

nav a {
    color: #9fc0d5;
    text-decoration: none;
}

.container {
    width: min(650px, 92%);
    margin: 45px auto;
}

.card {
    padding: 30px;

    background:
        rgba(7,20,34,.9);

    border:
        1px solid
        rgba(56,189,248,.15);

    border-radius: 20px;
}

h1 {
    margin-top: 0;
}

.subtitle {
    color: #708ca0;
    margin-bottom: 25px;
}

label {
    display: block;
    margin: 18px 0 8px;
    color: #a5c1d2;
}

input,
select {
    width: 100%;

    padding: 13px;

    background: #071321;

    color: white;

    border:
        1px solid
        rgba(255,255,255,.1);

    border-radius: 10px;

    outline: none;
}

input:focus,
select:focus {
    border-color: #38bdf8;
}

button {
    width: 100%;

    margin-top: 25px;

    border: 0;

    padding: 14px;

    border-radius: 11px;

    background:
        linear-gradient(
            135deg,
            #0284c7,
            #38bdf8
        );

    color: white;

    font-weight: 900;

    cursor: pointer;
}

.error {
    background: rgba(239,68,68,.1);
    border: 1px solid rgba(239,68,68,.3);
    color: #fca5a5;
    padding: 12px;
    border-radius: 10px;
}

.info {
    margin-top: 18px;
    padding: 14px;

    background: rgba(56,189,248,.05);

    border:
        1px solid
        rgba(56,189,248,.1);

    border-radius: 10px;

    color: #7192a7;

    font-size: 12px;
}

</style>

</head>

<body>

<nav>

<div class="logo">
    ⚔️ VergilPanel
</div>

<a href="/">
    ← Dashboard
</a>

</nav>

<div class="container">

<div class="card">

<h1>
    Create User
</h1>

<div class="subtitle">
    Create a new VPN account.
</div>

${
    error
        ? `<div class="error">${escapeHtml(error)}</div>`
        : ""
}

<form
    method="POST"
    action="/users/new">

<label>
    Username
</label>

<input
    name="username"
    placeholder="example"
    required>

<label>
    Protocol
</label>

<select
    name="protocol"
    required>

<option value="vless">
    VLESS
</option>

<option value="vmess">
    VMess
</option>

<option value="trojan">
    Trojan
</option>

<option value="shadowsocks">
    Shadowsocks
</option>

</select>

<label>
    Traffic Limit (GB)
</label>

<input
    type="number"
    name="traffic_limit"
    min="0"
    step="1"
    value="0">

<label>
    Expiration
</label>

<input
    type="datetime-local"
    name="expires_at">

<div class="info">
    Traffic value 0 means unlimited.
    <br><br>
    VLESS supports XHTTP + WebSocket.
    VMess and Trojan use WebSocket.
    Shadowsocks uses Railway TCP Proxy.
</div>

<button type="submit">
    CREATE USER
</button>

</form>

</div>

</div>

</body>

</html>
`;
}


// ------------------------------------------------------------
// Config page
// ------------------------------------------------------------

async function configPage(user, req) {
    const origin =
        getPublicOrigin(req);

    const protocol =
        normalizeProtocol(
            user.protocol
        );

    const links = [];

    if (protocol === "vless") {
        const vless =
            makeVlessLinks(
                user,
                origin
            );

        links.push({
            name: "VLESS XHTTP",
            value: vless.xhttp
        });

        links.push({
            name: "VLESS WebSocket",
            value: vless.websocket
        });
    }

    if (protocol === "vmess") {
        links.push({
            name: "VMess WebSocket",
            value: makeVmessLink(
                user,
                origin
            )
        });
    }

    if (protocol === "trojan") {
        links.push({
            name: "Trojan WebSocket",
            value: makeTrojanLink(
                user,
                origin
            )
        });
    }

    if (protocol === "shadowsocks") {
        links.push({
            name: "Shadowsocks TCP",
            value: makeShadowsocksLink(
                user
            )
        });
    }

    const subscriptionUrl =
        `${origin}/sub/${user.subscription_token}`;

    const subscriptionQr =
        await QRCode.toDataURL(
            subscriptionUrl
        );

    const configCards =
        await Promise.all(
            links.map(
                async link => ({
                    ...link,
                    qr:
                        await QRCode.toDataURL(
                            link.value
                        )
                })
            )
        );

    return `
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0">

<title>
    ${escapeHtml(user.username)}
    - VergilPanel
</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;

    min-height: 100vh;

    background:
        radial-gradient(
            circle at top,
            #102b48,
            #06101d 50%,
            #03070e
        );

    color: #e8f5ff;

    font-family:
        Arial,
        Helvetica,
        sans-serif;
}

nav {
    height: 70px;

    padding: 0 25px;

    display: flex;
    justify-content: space-between;
    align-items: center;

    background:
        rgba(3,10,20,.7);

    border-bottom:
        1px solid
        rgba(56,189,248,.12);
}

.logo {
    color: #38bdf8;
    font-weight: 900;
    font-size: 22px;
}

nav a {
    color: #9fc0d5;
    text-decoration: none;
}

.container {
    width: min(1000px, 94%);
    margin: 35px auto;
}

.header {
    margin-bottom: 25px;
}

.header h1 {
    margin-bottom: 5px;
}

.muted {
    color: #678499;
    font-size: 13px;
}

.badge {
    display: inline-block;

    margin-top: 12px;

    padding: 6px 12px;

    border-radius: 20px;

    color: #38bdf8;

    background:
        rgba(56,189,248,.08);

    border:
        1px solid
        rgba(56,189,248,.2);

    font-size: 12px;

    font-weight: 800;
}

.subscription {
    padding: 25px;

    background:
        rgba(7,20,34,.9);

    border:
        1px solid
        rgba(56,189,248,.14);

    border-radius: 18px;

    margin-bottom: 22px;

    text-align: center;
}

.subscription img {
    width: 190px;
    height: 190px;

    background: white;

    padding: 10px;

    border-radius: 12px;
}

.url {
    margin-top: 20px;

    padding: 13px;

    background: #030b14;

    border-radius: 10px;

    color: #7dd3fc;

    word-break: break-all;

    font-size: 12px;
}

.grid {
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(300px, 1fr)
        );

    gap: 18px;
}

.card {
    background:
        rgba(7,20,34,.9);

    border:
        1px solid
        rgba(56,189,248,.12);

    border-radius: 18px;

    padding: 22px;
}

.card h3 {
    margin-top: 0;
}

.qr {
    width: 170px;
    height: 170px;

    background: white;

    padding: 8px;

    border-radius: 10px;

    display: block;

    margin: 15px auto;
}

.link {
    padding: 12px;

    background: #030b14;

    border-radius: 9px;

    color: #9bdcff;

    font-size: 11px;

    word-break: break-all;
}

.brand {
    margin-top: 25px;

    padding: 20px;

    text-align: center;

    color: #7290a4;

    background:
        rgba(7,20,34,.65);

    border-radius: 15px;

    font-size: 12px;
}

</style>

</head>

<body>

<nav>

<div class="logo">
    ⚔️ VergilPanel
</div>

<a href="/">
    ← Dashboard
</a>

</nav>

<div class="container">

<div class="header">

<h1>
    ${escapeHtml(user.username)}
</h1>

<div class="muted">
    UUID:
    ${escapeHtml(user.uuid)}
</div>

<div class="badge">
    ${escapeHtml(
        protocolLabel(
            user.protocol
        )
    )}
</div>

</div>

<div class="subscription">

<h2>
    Subscription
</h2>

<img
    src="${subscriptionQr}"
    alt="Subscription QR">

<div class="url">
    ${escapeHtml(subscriptionUrl)}
</div>

</div>

<div class="grid">

${
    configCards
        .map(card => `
<div class="card">

<h3>
    ${escapeHtml(card.name)}
</h3>

<img
    class="qr"
    src="${card.qr}"
    alt="QR">

<div class="link">
    ${escapeHtml(card.value)}
</div>

</div>
`)
        .join("")
}

</div>

<div class="brand">

💙 ${escapeHtml(BRAND_1)}

<br><br>

🖤 ${escapeHtml(BRAND_2)}

<br><br>

POWERED BY YASIN BEHZAD

</div>

</div>

</body>

</html>
`;
}


// ------------------------------------------------------------
// Settings
// ------------------------------------------------------------

function settingsPage(message = "") {
    const admin =
        getAdmin();

    return `
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0">

<title>Settings - VergilPanel</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;

    min-height: 100vh;

    background:
        radial-gradient(
            circle at top,
            #102b48,
            #06101d 50%,
            #03070e
        );

    color: #e8f5ff;

    font-family: Arial, sans-serif;
}

nav {
    height: 70px;

    padding: 0 25px;

    display: flex;
    justify-content: space-between;
    align-items: center;

    background:
        rgba(3,10,20,.7);

    border-bottom:
        1px solid
        rgba(56,189,248,.12);
}

.logo {
    color: #38bdf8;
    font-weight: 900;
    font-size: 22px;
}

nav a {
    color: #9fc0d5;
    text-decoration: none;
}

.container {
    width: min(600px, 92%);
    margin: 45px auto;
}

.card {
    padding: 30px;

    background:
        rgba(7,20,34,.9);

    border:
        1px solid
        rgba(56,189,248,.12);

    border-radius: 20px;
}

label {
    display: block;
    margin: 18px 0 8px;
    color: #a3bfce;
}

input {
    width: 100%;
    padding: 13px;

    background: #071321;
    color: white;

    border:
        1px solid
        rgba(255,255,255,.1);

    border-radius: 10px;
}

button {
    width: 100%;
    padding: 14px;
    margin-top: 25px;

    border: 0;
    border-radius: 10px;

    background:
        linear-gradient(
            135deg,
            #0284c7,
            #38bdf8
        );

    color: white;
    font-weight: 900;
}

.message {
    padding: 12px;

    margin-bottom: 15px;

    background:
        rgba(52,211,153,.1);

    color: #6ee7b7;

    border-radius: 10px;
}

</style>

</head>

<body>

<nav>

<div class="logo">
    ⚔️ VergilPanel
</div>

<a href="/">
    ← Dashboard
</a>

</nav>

<div class="container">

<div class="card">

<h1>
    Settings
</h1>

${
    message
        ? `<div class="message">${escapeHtml(message)}</div>`
        : ""
}

<form
    method="POST"
    action="/settings">

<label>
    Admin Username
</label>

<input
    name="username"
    value="${escapeHtml(
        admin?.username || ""
    )}"
    required>

<label>
    New Password
</label>

<input
    type="password"
    name="password"
    placeholder="Leave blank to keep current password">

<button type="submit">
    SAVE SETTINGS
</button>

</form>

</div>

</div>

</body>

</html>
`;
}


// ------------------------------------------------------------
// HTTP request handler
// ------------------------------------------------------------

async function handleRequest(req, res) {
    try {
        const url =
            new URL(
                req.url,
                `http://${getPublicHost(req)}`
            );

        const pathname =
            url.pathname;


        // ----------------------------------------------------
        // XHTTP
        // ----------------------------------------------------

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


        // ----------------------------------------------------
        // Subscription
        // ----------------------------------------------------

        if (
            pathname.startsWith("/sub/")
        ) {
            const token =
                pathname.slice(
                    "/sub/".length
                );

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE subscription_token = ?
                      AND status = 'active'
                `).get(token);

            if (!user) {
                sendJson(
                    res,
                    {
                        ok: false,
                        error: "Invalid subscription"
                    },
                    404
                );

                return;
            }

            const subscription =
                makeSubscription(
                    user,
                    getPublicOrigin(req)
                );

            res.writeHead(200, {
                "Content-Type":
                    "text/plain; charset=utf-8",

                "Cache-Control":
                    "no-store",

                "Profile-Update-Interval":
                    "1"
            });

            res.end(subscription);

            return;
        }


        // ----------------------------------------------------
        // Health
        // ----------------------------------------------------

        if (
            pathname === "/health"
        ) {
            sendJson(
                res,
                {
                    ok: true,
                    version: VERSION,
                    xray:
                        Boolean(xrayProcess),
                    users:
                        activeUsers().length
                }
            );

            return;
        }


        // ----------------------------------------------------
        // Login GET
        // ----------------------------------------------------

        if (
            pathname === "/login" &&
            req.method === "GET"
        ) {
            if (getSession(req)) {
                redirect(
                    res,
                    "/"
                );

                return;
            }

            sendHtml(
                res,
                loginPage()
            );

            return;
        }


        // ----------------------------------------------------
        // Login POST
        // ----------------------------------------------------

        if (
            pathname === "/login" &&
            req.method === "POST"
        ) {
            const form =
                await readForm(req);

            const username =
                String(
                    form.get("username") || ""
                );

            const password =
                String(
                    form.get("password") || ""
                );

            const admin =
                db.prepare(`
                    SELECT *
                    FROM admins
                    WHERE username = ?
                `).get(username);

            if (
                !admin ||
                hashPassword(password) !==
                    admin.password_hash
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
                    adminId: admin.id,
                    username: admin.username
                }
            );

            res.writeHead(
                302,
                {
                    Location: "/",
                    "Set-Cookie":
                        `session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax`
                }
            );

            res.end();

            return;
        }


        // ----------------------------------------------------
        // Logout
        // ----------------------------------------------------

        if (
            pathname === "/logout"
        ) {
            const cookies =
                parseCookies(req);

            if (cookies.session) {
                sessions.delete(
                    cookies.session
                );
            }

            res.writeHead(
                302,
                {
                    Location: "/login",
                    "Set-Cookie":
                        "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
                }
            );

            res.end();

            return;
        }


        // ----------------------------------------------------
        // Authentication
        // ----------------------------------------------------

        const session =
            requireAuth(
                req,
                res
            );

        if (!session) {
            return;
        }


        // ----------------------------------------------------
        // Dashboard
        // ----------------------------------------------------

        if (
            pathname === "/" ||
            pathname === "/dashboard"
        ) {
            sendHtml(
                res,
                dashboardPage(
                    allUsers(),
                    req
                )
            );

            return;
        }


        // ----------------------------------------------------
        // Settings GET
        // ----------------------------------------------------

        if (
            pathname === "/settings" &&
            req.method === "GET"
        ) {
            sendHtml(
                res,
                settingsPage()
            );

            return;
        }


        // ----------------------------------------------------
        // Settings POST
        // ----------------------------------------------------

        if (
            pathname === "/settings" &&
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

            if (!username) {
                sendHtml(
                    res,
                    settingsPage(
                        "Username cannot be empty."
                    )
                );

                return;
            }

            if (password) {
                db.prepare(`
                    UPDATE admins
                    SET username = ?,
                        password_hash = ?
                    WHERE id = ?
                `).run(
                    username,
                    hashPassword(password),
                    session.adminId
                );
            } else {
                db.prepare(`
                    UPDATE admins
                    SET username = ?
                    WHERE id = ?
                `).run(
                    username,
                    session.adminId
                );
            }

            session.username =
                username;

            sendHtml(
                res,
                settingsPage(
                    "Settings saved successfully."
                )
            );

            return;
        }


        // ----------------------------------------------------
        // New user GET
        // ----------------------------------------------------

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


        // ----------------------------------------------------
        // New user POST
        // ----------------------------------------------------

        if (
            pathname === "/users/new" &&
            req.method === "POST"
        ) {
            const form =
                await readForm(req);

            try {
                const user =
                    createUser(form);

                await restartXray();

                redirect(
                    res,
                    `/users/config?id=${user.id}`
                );
            } catch (error) {
                console.error(
                    "Create user error:",
                    error
                );

                sendHtml(
                    res,
                    newUserPage(
                        error.message
                    ),
                    400
                );
            }

            return;
        }


        // ----------------------------------------------------
        // User config
        // ----------------------------------------------------

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
                    "<h1>User not found</h1>",
                    404
                );

                return;
            }

            sendHtml(
                res,
                await configPage(
                    user,
                    req
                )
            );

            return;
        }


        // ----------------------------------------------------
        // Toggle user
        // ----------------------------------------------------

        if (
            pathname === "/users/toggle" &&
            req.method === "POST"
        ) {
            const form =
                await readForm(req);

            const id =
                Number(
                    form.get("id")
                );

            const user =
                db.prepare(`
                    SELECT *
                    FROM users
                    WHERE id = ?
                `).get(id);

            if (user) {
                const next =
                    user.status === "active"
                        ? "disabled"
                        : "active";

                db.prepare(`
                    UPDATE users
                    SET status = ?
                    WHERE id = ?
                `).run(
                    next,
                    id
                );

                await restartXray();
            }

            redirect(
                res,
                "/"
            );

            return;
        }


        // ----------------------------------------------------
        // Delete user
        // ----------------------------------------------------

        if (
            pathname === "/users/delete" &&
            req.method === "POST"
        ) {
            const form =
                await readForm(req);

            const id =
                Number(
                    form.get("id")
                );

            db.prepare(`
                DELETE FROM users
                WHERE id = ?
            `).run(id);

            await restartXray();

            redirect(
                res,
                "/"
            );

            return;
        }


        // ----------------------------------------------------
        // 404
        // ----------------------------------------------------

        sendHtml(
            res,
            `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>404</title>
<style>
body {
    background:#030812;
    color:#38bdf8;
    font-family:Arial;
    text-align:center;
    padding-top:100px;
}
</style>
</head>
<body>
<h1>404</h1>
<p>VergilPanel - Page not found.</p>
<a href="/" style="color:#38bdf8">
Dashboard
</a>
</body>
</html>
            `,
            404
        );

    } catch (error) {
        console.error(
            "Request error:",
            error
        );

        if (!res.headersSent) {
            sendJson(
                res,
                {
                    ok: false,
                    error: error.message
                },
                500
            );
        }
    }
}


// ------------------------------------------------------------
// HTTP server
// ------------------------------------------------------------

const server =
    http.createServer(
        handleRequest
    );


// ------------------------------------------------------------
// WebSocket upgrade routing
// ------------------------------------------------------------

server.on(
    "upgrade",
    (req, socket, head) => {
        try {
            const pathname =
                new URL(
                    req.url,
                    `http://${req.headers.host || "localhost"}`
                ).pathname;


            if (
                pathname === VLESS_WS_PATH ||
                pathname.startsWith(
                    `${VLESS_WS_PATH}/`
                )
            ) {
                proxyWebSocket(
                    req,
                    socket,
                    head,
                    XRAY_VLESS_WS_PORT
                );

                return;
            }


            if (
                pathname === VMESS_WS_PATH ||
                pathname.startsWith(
                    `${VMESS_WS_PATH}/`
                )
            ) {
                proxyWebSocket(
                    req,
                    socket,
                    head,
                    XRAY_VMESS_WS_PORT
                );

                return;
            }


            if (
                pathname === TROJAN_WS_PATH ||
                pathname.startsWith(
                    `${TROJAN_WS_PATH}/`
                )
            ) {
                proxyWebSocket(
                    req,
                    socket,
                    head,
                    XRAY_TROJAN_WS_PORT
                );

                return;
            }

            socket.destroy();

        } catch (error) {
            console.error(
                "Upgrade error:",
                error
            );

            try {
                socket.destroy();
            } catch {}
        }
    }
);


// ------------------------------------------------------------
// TCP proxy listener
// ------------------------------------------------------------

const tcpServer =
    net.createServer(
        socket => {
            proxyTcpToXray(
                socket
            );
        }
    );


// ------------------------------------------------------------
// Startup
// ------------------------------------------------------------

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
            `👤 Login: admin / admin`
        );

        console.log(
            `💙 POWERED BY YASIN BEHZAD`
        );

        console.log(
            `🖤 ${BRAND_2}`
        );

        console.log(
            `🌐 HTTP: ${PORT}`
        );

        console.log(
            `⚔️ XHTTP: ${XRAY_XHTTP_PORT}`
        );

        console.log(
            `⚔️ VLESS WS: ${XRAY_VLESS_WS_PORT}`
        );

        console.log(
            `⚔️ VMess WS: ${XRAY_VMESS_WS_PORT}`
        );

        console.log(
            `⚔️ Trojan WS: ${XRAY_TROJAN_WS_PORT}`
        );

        console.log(
            `⚔️ Shadowsocks TCP: ${XRAY_SS_PORT}`
        );
    }
);


// ------------------------------------------------------------
// Raw TCP server
//
// IMPORTANT:
// Railway TCP Proxy must point to XRAY_SS_PORT.
// ------------------------------------------------------------

tcpServer.listen(
    XRAY_SS_PORT,
    "0.0.0.0",
    () => {
        console.log(
            `🔌 TCP listener running on 0.0.0.0:${XRAY_SS_PORT}`
        );
    }
);


// ------------------------------------------------------------
// Shutdown
// ------------------------------------------------------------

async function shutdown(signal) {
    console.log(
        `\n🛑 Received ${signal}. Shutting down...`
    );

    try {
        await stopXray();
    } catch {}

    try {
        server.close();
    } catch {}

    try {
        tcpServer.close();
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
