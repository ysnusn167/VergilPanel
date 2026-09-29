import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import { spawn } from "node:child_process";
import net from "node:net";

import Database from "better-sqlite3";
import QRCode from "qrcode";


// ============================================================
// VergilPanel
// Version 1.1.0
// ============================================================

const VERSION = "1.1.0";

const PORT =
    Number(process.env.PORT || 8080);

const HOST = "0.0.0.0";

const DATA_DIR =
    process.env.DATA_DIR || "/app/data";

const DB_PATH =
    `${DATA_DIR}/vergilpanel.db`;

const XRAY_BIN =
    process.env.XRAY_BIN ||
    "/opt/xray/xray";

const XRAY_CONFIG =
    process.env.XRAY_CONFIG ||
    "/app/xray/generated-config.json";


// ============================================================
// Internal Xray ports
// ============================================================

const XRAY_XHTTP_PORT =
    Number(
        process.env.XRAY_XHTTP_PORT || 10001
    );

const XRAY_VLESS_WS_PORT =
    Number(
        process.env.XRAY_VLESS_WS_PORT || 10002
    );

const XRAY_VMESS_WS_PORT =
    Number(
        process.env.XRAY_VMESS_WS_PORT || 10003
    );

const XRAY_TROJAN_WS_PORT =
    Number(
        process.env.XRAY_TROJAN_WS_PORT || 10004
    );

const XRAY_SS_PORT =
    Number(
        process.env.XRAY_SS_PORT || 10005
    );


// ============================================================
// Internal paths
// ============================================================

const XHTTP_PATH =
    process.env.XHTTP_PATH || "/xhttp";

const VLESS_WS_PATH =
    process.env.VLESS_WS_PATH || "/ws";

const VMESS_WS_PATH =
    process.env.VMESS_WS_PATH || "/vmess";

const TROJAN_WS_PATH =
    process.env.TROJAN_WS_PATH || "/trojan";


// ============================================================
// Branding
// ============================================================

const BRAND_1 =
    "ساخته شده توسط یاسین - پنل کاملا رایگان و غیرقابل فروش";

const BRAND_2 =
    "به یاد زنده یاد علی نور 🖤";


// ============================================================
// Runtime
// ============================================================

let xrayProcess = null;

let stoppingXray = false;

let xrayRestarting = false;

const sessions = new Map();


// ============================================================
// Files / Database
// ============================================================

await fs.mkdir(
    DATA_DIR,
    { recursive: true }
);

await fs.mkdir(
    "/app/xray",
    { recursive: true }
);

const db =
    new Database(DB_PATH);

db.pragma("journal_mode = WAL");


// ============================================================
// Database
// ============================================================

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

    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),

        panel_host TEXT NOT NULL DEFAULT '',

        tcp_proxy_host TEXT NOT NULL DEFAULT '',

        tcp_proxy_port INTEGER NOT NULL DEFAULT 0,

        updated_at TEXT NOT NULL
    );
`);


// ============================================================
// Settings initialization
// ============================================================

function ensureSettings() {
    const existing =
        db.prepare(`
            SELECT *
            FROM settings
            WHERE id = 1
        `).get();

    if (existing) {
        return existing;
    }

    db.prepare(`
        INSERT INTO settings
        (
            id,
            panel_host,
            tcp_proxy_host,
            tcp_proxy_port,
            updated_at
        )
        VALUES
        (
            1,
            ?,
            ?,
            ?,
            ?
        )
    `).run(
        process.env.PANEL_HOST || "",
        process.env.TCP_PROXY_DOMAIN ||
            process.env.RAILWAY_TCP_PROXY_DOMAIN ||
            "",
        Number(
            process.env.TCP_PROXY_PORT ||
            process.env.RAILWAY_TCP_PROXY_PORT ||
            0
        ),
        nowIso()
    );

    return db.prepare(`
        SELECT *
        FROM settings
        WHERE id = 1
    `).get();
}

ensureSettings();


// ============================================================
// Helpers
// ============================================================

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

    const cookie =
        req.headers.cookie;

    if (!cookie) {
        return result;
    }

    for (const item of cookie.split(";")) {
        const index =
            item.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            item.slice(0, index).trim();

        const value =
            item.slice(index + 1).trim();

        result[key] =
            decodeURIComponent(value);
    }

    return result;
}


function getSession(req) {
    const cookies =
        parseCookies(req);

    if (!cookies.session) {
        return null;
    }

    return (
        sessions.get(
            cookies.session
        ) || null
    );
}


function redirect(res, location) {
    res.writeHead(302, {
        Location: location
    });

    res.end();
}


function sendHtml(
    res,
    html,
    status = 200
) {
    res.writeHead(status, {
        "Content-Type":
            "text/html; charset=utf-8",

        "Cache-Control":
            "no-store"
    });

    res.end(html);
}


function sendJson(
    res,
    data,
    status = 200
) {
    res.writeHead(status, {
        "Content-Type":
            "application/json; charset=utf-8",

        "Cache-Control":
            "no-store"
    });

    res.end(
        JSON.stringify(data)
    );
}


function readBody(req) {
    return new Promise(
        (resolve, reject) => {
            let body = "";

            req.on(
                "data",
                chunk => {
                    body +=
                        chunk.toString();

                    if (
                        body.length >
                        5_000_000
                    ) {
                        req.destroy();

                        reject(
                            new Error(
                                "Request body too large"
                            )
                        );
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
    const body =
        await readBody(req);

    return new URLSearchParams(body);
}


function requireAuth(req, res) {
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


// ============================================================
// Settings helpers
// ============================================================

function getSettings() {
    return db.prepare(`
        SELECT *
        FROM settings
        WHERE id = 1
    `).get();
}


function getPanelHost(req) {
    const settings =
        getSettings();

    if (
        settings &&
        settings.panel_host
    ) {
        return String(
            settings.panel_host
        )
            .replace(/^https?:\/\//i, "")
            .replace(/\/+$/, "");
    }

    const forwardedHost =
        req.headers["x-forwarded-host"] ||
        req.headers.host ||
        "localhost";

    return String(
        forwardedHost
    )
        .split(",")[0]
        .trim();
}


function getPublicOrigin(req) {
    return `https://${getPanelHost(req)}`;
}


function getTcpHost() {
    const settings =
        getSettings();

    return String(
        settings?.tcp_proxy_host || ""
    ).trim();
}


function getTcpPort() {
    const settings =
        getSettings();

    return Number(
        settings?.tcp_proxy_port || 0
    );
}


// ============================================================
// Users
// ============================================================

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


// ============================================================
// Admin
// ============================================================

function getAdmin() {
    return db.prepare(`
        SELECT *
        FROM admins
        ORDER BY id ASC
        LIMIT 1
    `).get();
}


function ensureDefaultAdmin() {
    const existing =
        getAdmin();

    if (existing) {
        return;
    }

    const username =
        process.env.ADMIN_USERNAME ||
        "admin";

    const password =
        process.env.ADMIN_PASSWORD ||
        "admin";

    db.prepare(`
        INSERT INTO admins
        (
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


// ============================================================
// Xray configuration
// ============================================================

function generateXrayConfig() {
    const users =
        activeUsers();

    const vlessClients =
        users.map(user => ({
            id: user.uuid,
            email: user.username
        }));

    const vmessClients =
        users.map(user => ({
            id: user.uuid,
            email: user.username,
            alterId: 0
        }));

    const trojanClients =
        users.map(user => ({
            password: user.uuid,
            email: user.username
        }));

    const shadowsocksClients =
        users.map(user => ({
            password: user.uuid,
            email: user.username
        }));

    const inbounds = [];


// ------------------------------------------------------------
// VLESS XHTTP
// ------------------------------------------------------------

    if (vlessClients.length > 0) {
        inbounds.push({
            listen: "127.0.0.1",

            port:
                XRAY_XHTTP_PORT,

            protocol: "vless",

            settings: {
                clients:
                    vlessClients,

                decryption: "none"
            },

            streamSettings: {
                network: "xhttp",

                security: "none",

                xhttpSettings: {
                    path:
                        XHTTP_PATH,

                    mode: "auto"
                }
            }
        });
    }


// ------------------------------------------------------------
// VLESS WebSocket
// ------------------------------------------------------------

    if (vlessClients.length > 0) {
        inbounds.push({
            listen: "127.0.0.1",

            port:
                XRAY_VLESS_WS_PORT,

            protocol: "vless",

            settings: {
                clients:
                    vlessClients,

                decryption: "none"
            },

            streamSettings: {
                network: "websocket",

                security: "none",

                wsSettings: {
                    path:
                        VLESS_WS_PATH
                }
            }
        });
    }


// ------------------------------------------------------------
// VMess WebSocket
// ------------------------------------------------------------

    if (vmessClients.length > 0) {
        inbounds.push({
            listen: "127.0.0.1",

            port:
                XRAY_VMESS_WS_PORT,

            protocol: "vmess",

            settings: {
                clients:
                    vmessClients
            },

            streamSettings: {
                network: "websocket",

                security: "none",

                wsSettings: {
                    path:
                        VMESS_WS_PATH
                }
            }
        });
    }


// ------------------------------------------------------------
// Trojan WebSocket
// ------------------------------------------------------------

    if (trojanClients.length > 0) {
        inbounds.push({
            listen: "127.0.0.1",

            port:
                XRAY_TROJAN_WS_PORT,

            protocol: "trojan",

            settings: {
                clients:
                    trojanClients
            },

            streamSettings: {
                network: "websocket",

                security: "none",

                wsSettings: {
                    path:
                        TROJAN_WS_PATH
                }
            }
        });
    }


// ------------------------------------------------------------
// Shadowsocks TCP
// ------------------------------------------------------------

    if (shadowsocksClients.length > 0) {
        inbounds.push({
            listen: "0.0.0.0",

            port:
                XRAY_SS_PORT,

            protocol: "shadowsocks",

            settings: {
                method:
                    "chacha20-ietf-poly1305",

                clients:
                    shadowsocksClients,

                network:
                    "tcp,udp"
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

            stoppingXray = true;

            const processToStop =
                xrayProcess;

            xrayProcess = null;

            try {
                processToStop.kill(
                    "SIGTERM"
                );
            } catch {}

            setTimeout(
                () => {
                    try {
                        processToStop.kill(
                            "SIGKILL"
                        );
                    } catch {}

                    stoppingXray = false;

                    resolve();
                },
                2000
            );
        }
    );
}


async function startXray() {
    await writeXrayConfig();

    if (xrayProcess) {
        return;
    }

    stoppingXray = false;

    console.log(
        `⚙️ Xray binary: ${XRAY_BIN}`
    );

    const child =
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

    xrayProcess =
        child;

    child.stdout.on(
        "data",
        data => {
            process.stdout.write(
                `[XRAY] ${data}`
            );
        }
    );

    child.stderr.on(
        "data",
        data => {
            process.stderr.write(
                `[XRAY] ${data}`
            );
        }
    );

    child.on(
        "error",
        error => {
            console.error(
                "❌ Xray process error:",
                error
            );

            xrayProcess = null;
        }
    );

    child.on(
        "exit",
        async (
            code,
            signal
        ) => {
            console.log(
                `⚠️ Xray exited. code=${code} signal=${signal}`
            );

            xrayProcess = null;

            if (
                !stoppingXray &&
                !xrayRestarting
            ) {
                xrayRestarting = true;

                setTimeout(
                    async () => {
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
                    },
                    1500
                );
            }
        }
    );
}


async function restartXray() {
    await stopXray();
    await startXray();
}


// ============================================================
// VLESS
// ============================================================

function makeVlessLinks(
    user,
    req
) {
    const domain =
        getPanelHost(req);

    const xhttpParams =
        new URLSearchParams({
            encryption: "none",

            security: "tls",

            type: "xhttp",

            path:
                XHTTP_PATH,

            host:
                domain,

            sni:
                domain,

            mode: "auto"
        });

    const wsParams =
        new URLSearchParams({
            encryption: "none",

            security: "tls",

            type: "ws",

            path:
                VLESS_WS_PATH,

            host:
                domain,

            sni:
                domain
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


// ============================================================
// VMess
// ============================================================

function makeVmessLink(
    user,
    req
) {
    const domain =
        getPanelHost(req);

    const config = {
        v: "2",

        ps:
            `${user.username}-VMess`,

        add:
            domain,

        port:
            "443",

        id:
            user.uuid,

        aid:
            "0",

        scy:
            "auto",

        net:
            "ws",

        type:
            "none",

        host:
            domain,

        path:
            VMESS_WS_PATH,

        tls:
            "tls",

        sni:
            domain
    };

    return (
        `vmess://${Buffer
            .from(
                JSON.stringify(config),
                "utf8"
            )
            .toString("base64")}`
    );
}


// ============================================================
// Trojan
// ============================================================

function makeTrojanLink(
    user,
    req
) {
    const domain =
        getPanelHost(req);

    const params =
        new URLSearchParams({
            type:
                "ws",

            security:
                "tls",

            path:
                TROJAN_WS_PATH,

            host:
                domain,

            sni:
                domain
        });

    return (
        `trojan://${encodeURIComponent(
            user.uuid
        )}@${domain}:443?${params.toString()}#${encodeURIComponent(
            `${user.username}-Trojan`
        )}`
    );
}


// ============================================================
// Shadowsocks
// ============================================================

function makeShadowsocksLink(
    user
) {
    const host =
        getTcpHost();

    const port =
        getTcpPort();

    if (
        !host ||
        !port
    ) {
        return "";
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
        `ss://${userInfo}@${host}:${port}#${encodeURIComponent(
            `${user.username}-Shadowsocks`
        )}`
    );
}


// ============================================================
// Dummy configs
// ============================================================

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


// ============================================================
// Subscription
// ============================================================

function makeSubscription(
    user,
    req
) {
    const links = [];

    const vless =
        makeVlessLinks(
            user,
            req
        );

    links.push(
        vless.xhttp
    );

    links.push(
        vless.websocket
    );

    links.push(
        makeVmessLink(
            user,
            req
        )
    );

    links.push(
        makeTrojanLink(
            user,
            req
        )
    );

    const ss =
        makeShadowsocksLink(
            user
        );

    if (ss) {
        links.push(ss);
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


// ============================================================
// User creation
// ============================================================

function createUser(form) {
    const username =
        String(
            form.get("username") || ""
        ).trim();

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
            "Username is required."
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
            "Username already exists."
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
            VALUES
            (
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
            trafficLimitBytes,
            expiresAt || null,
            subscriptionToken,
            nowIso()
        );

    console.log(
        `👤 User created: ${username}`
    );

    return db.prepare(`
        SELECT *
        FROM users
        WHERE id = ?
    `).get(
        result.lastInsertRowid
    );
}


// ============================================================
// HTTP -> Xray proxy
// ============================================================

function proxyHttpToXray(
    req,
    res,
    targetPort
) {
    const options = {
        hostname:
            "127.0.0.1",

        port:
            targetPort,

        path:
            req.url,

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

            if (
                !res.headersSent
            ) {
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


// ============================================================
// WebSocket proxy
// ============================================================

function proxyWebSocket(
    req,
    clientSocket,
    head,
    targetPort
) {
    const upstream =
        net.connect({
            host:
                "127.0.0.1",

            port:
                targetPort
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


// ============================================================
// Login page
// ============================================================

function loginPage(
    error = ""
) {
    return `
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1">

<title>
VergilPanel Login
</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;

    min-height: 100vh;

    display: flex;

    align-items: center;

    justify-content: center;

    background:
        radial-gradient(
            circle at top,
            #102a46,
            #07111e 45%,
            #030812
        );

    color: white;

    font-family:
        Arial,
        sans-serif;
}

.card {
    width:
        min(420px,92%);

    padding: 35px;

    background:
        rgba(8,21,36,.94);

    border:
        1px solid
        rgba(56,189,248,.2);

    border-radius: 22px;

    box-shadow:
        0 25px 80px
        rgba(0,0,0,.55);
}

.logo {
    text-align: center;

    font-size: 32px;

    font-weight: 900;

    color: #38bdf8;
}

.sub {
    text-align: center;

    color: #718da2;

    margin:
        7px 0 28px;
}

label {
    display: block;

    margin:
        12px 0 7px;

    color: #a6c0d0;
}

input {
    width: 100%;

    padding: 13px;

    border-radius: 10px;

    border:
        1px solid
        rgba(255,255,255,.1);

    background:
        #071321;

    color: white;

    outline: none;
}

input:focus {
    border-color:
        #38bdf8;
}

button {
    width: 100%;

    margin-top: 20px;

    padding: 14px;

    border: 0;

    border-radius: 11px;

    color: white;

    font-weight: 900;

    background:
        linear-gradient(
            135deg,
            #0284c7,
            #38bdf8
        );
}

.error {
    padding: 12px;

    margin-bottom: 15px;

    border-radius: 10px;

    color: #fca5a5;

    background:
        rgba(239,68,68,.1);

    border:
        1px solid
        rgba(239,68,68,.25);
}

</style>

</head>

<body>

<div class="card">

<div class="logo">
⚔️ VergilPanel
</div>

<div class="sub">
v${VERSION}
</div>

${
    error
        ? `<div class="error">${escapeHtml(error)}</div>`
        : ""
}

<form
    method="POST"
    action="/login">

<label>
Username
</label>

<input
    name="username"
    required
    autocomplete="username">

<label>
Password
</label>

<input
    type="password"
    name="password"
    required
    autocomplete="current-password">

<button>
LOGIN
</button>

</form>

</div>

</body>

</html>
`;
}


// ============================================================
// Dashboard
// ============================================================

function dashboardPage(
    users
) {
    const rows =
        users.map(
            user => {
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
AUTO
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
action="/users/toggle">

<input
type="hidden"
name="id"
value="${user.id}">

<button
class="btn small secondary">

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
onsubmit="return confirm('Delete this user?')">

<input
type="hidden"
name="id"
value="${user.id}">

<button
class="btn small danger">

DELETE

</button>

</form>

</div>

</td>

</tr>
`;
            }
        )
        .join("");

    return `
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1">

<title>
VergilPanel
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
        sans-serif;
}

nav {
    height: 70px;

    padding:
        0 25px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    background:
        rgba(3,10,20,.72);

    border-bottom:
        1px solid
        rgba(56,189,248,.12);
}

.logo {
    color:
        #38bdf8;

    font-size:
        22px;

    font-weight:
        900;
}

.navlinks {
    display: flex;

    gap: 8px;

    flex-wrap: wrap;
}

.navlinks a {
    color:
        #9fc0d5;

    text-decoration:
        none;

    padding:
        8px 12px;

    border-radius:
        8px;
}

.navlinks a:hover {
    background:
        rgba(56,189,248,.1);

    color: white;
}

.container {
    width:
        min(1250px,94%);

    margin:
        35px auto;
}

.hero {
    display: flex;

    justify-content:
        space-between;

    align-items:
        center;

    gap: 20px;

    margin-bottom:
        25px;
}

.hero h1 {
    margin:
        0 0 6px;
}

.hero p {
    color:
        #7897ad;
}

.btn {
    display:
        inline-block;

    border:
        0;

    padding:
        11px 16px;

    border-radius:
        10px;

    background:
        linear-gradient(
            135deg,
            #0284c7,
            #38bdf8
        );

    color:
        white;

    font-weight:
        800;

    text-decoration:
        none;

    cursor:
        pointer;
}

.small {
    padding:
        7px 9px;

    font-size:
        10px;
}

.secondary {
    background:
        #16283b;
}

.danger {
    background:
        #7f1d1d;
}

.card {
    background:
        rgba(7,20,34,.9);

    border:
        1px solid
        rgba(56,189,248,.12);

    border-radius:
        18px;

    overflow:
        hidden;
}

table {
    width:
        100%;

    border-collapse:
        collapse;
}

th,
td {
    padding:
        16px;

    text-align:
        left;

    border-bottom:
        1px solid
        rgba(255,255,255,.05);
}

th {
    color:
        #7394aa;

    font-size:
        11px;

    text-transform:
        uppercase;
}

.muted {
    margin-top:
        5px;

    color:
        #526f83;

    font-size:
        10px;

    max-width:
        230px;

    overflow:
        hidden;

    text-overflow:
        ellipsis;
}

.active,
.disabled {
    padding:
        5px 9px;

    border-radius:
        20px;

    font-size:
        10px;
}

.active {
    color:
        #34d399;

    background:
        rgba(52,211,153,.1);
}

.disabled {
    color:
        #fb7185;

    background:
        rgba(251,113,133,.1);
}

.actions {
    display:
        flex;

    gap:
        5px;

    flex-wrap:
        wrap;
}

.actions form {
    display:
        inline;
}

.empty {
    padding:
        60px;

    text-align:
        center;

    color:
        #658197;
}

.brand {
    margin-top:
        25px;

    text-align:
        center;

    color:
        #58758a;

    font-size:
        11px;
}

@media(max-width:800px) {

    .hero {
        flex-direction:
            column;

        align-items:
            flex-start;
    }

    table {
        font-size:
            11px;
    }

    th,
    td {
        padding:
            10px 7px;
    }

}

</style>

</head>

<body>

<nav>

<div class="logo">
⚔️ VergilPanel
<span
style="font-size:11px;color:#647f94">
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
Manage users and automatically generate all configurations.
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

<th>
User
</th>

<th>
Configs
</th>

<th>
Traffic
</th>

<th>
Expiration
</th>

<th>
Status
</th>

<th>
Actions
</th>

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


// ============================================================
// New user
// ============================================================

function newUserPage(
    error = ""
) {
    return `
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1">

<title>
Create User
</title>

<style>

* {
    box-sizing:
        border-box;
}

body {
    margin:
        0;

    min-height:
        100vh;

    background:
        radial-gradient(
            circle at top,
            #102b48,
            #06101d 50%,
            #03070e
        );

    color:
        #e8f5ff;

    font-family:
        Arial,
        sans-serif;
}

nav {
    height:
        70px;

    padding:
        0 25px;

    display:
        flex;

    justify-content:
        space-between;

    align-items:
        center;

    background:
        rgba(3,10,20,.7);

    border-bottom:
        1px solid
        rgba(56,189,248,.12);
}

.logo {
    color:
        #38bdf8;

    font-weight:
        900;

    font-size:
        22px;
}

nav a {
    color:
        #9fc0d5;

    text-decoration:
        none;
}

.container {
    width:
        min(650px,92%);

    margin:
        45px auto;
}

.card {
    padding:
        30px;

    background:
        rgba(7,20,34,.92);

    border:
        1px solid
        rgba(56,189,248,.15);

    border-radius:
        20px;
}

h1 {
    margin-top:
        0;
}

.subtitle {
    color:
        #708ca0;

    margin-bottom:
        25px;
}

label {
    display:
        block;

    margin:
        18px 0 8px;

    color:
        #a5c1d2;
}

input {
    width:
        100%;

    padding:
        13px;

    background:
        #071321;

    color:
        white;

    border:
        1px solid
        rgba(255,255,255,.1);

    border-radius:
        10px;

    outline:
        none;
}

input:focus {
    border-color:
        #38bdf8;
}

button {
    width:
        100%;

    margin-top:
        25px;

    padding:
        14px;

    border:
        0;

    border-radius:
        11px;

    background:
        linear-gradient(
            135deg,
            #0284c7,
            #38bdf8
        );

    color:
        white;

    font-weight:
        900;

    cursor:
        pointer;
}

.info {
    margin-top:
        18px;

    padding:
        14px;

    background:
        rgba(56,189,248,.05);

    border:
        1px solid
        rgba(56,189,248,.1);

    border-radius:
        10px;

    color:
        #7192a7;

    font-size:
        12px;
}

.error {
    padding:
        12px;

    margin-bottom:
        15px;

    border-radius:
        10px;

    color:
        #fca5a5;

    background:
        rgba(239,68,68,.1);

    border:
        1px solid
        rgba(239,68,68,.3);
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
One button generates all supported configurations automatically.
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

<b>
Automatic configuration:
</b>

<br><br>

VLESS XHTTP<br>
VLESS WebSocket<br>
VMess WebSocket<br>
Trojan WebSocket<br>
Shadowsocks TCP

<br><br>

No protocol selection is required.

<br>

Traffic value 0 means unlimited.

</div>

<button type="submit">
⚡ ساخت کانفیگ
</button>

</form>

</div>

</div>

</body>

</html>
`;
}


// ============================================================
// Config page
// ============================================================

async function configPage(
    user,
    req
) {
    const links = [];

    const vless =
        makeVlessLinks(
            user,
            req
        );

    links.push({
        name:
            "VLESS XHTTP",

        value:
            vless.xhttp
    });

    links.push({
        name:
            "VLESS WebSocket",

        value:
            vless.websocket
    });

    links.push({
        name:
            "VMess WebSocket",

        value:
            makeVmessLink(
                user,
                req
            )
    });

    links.push({
        name:
            "Trojan WebSocket",

        value:
            makeTrojanLink(
                user,
                req
            )
    });

    const ss =
        makeShadowsocksLink(
            user
        );

    if (ss) {
        links.push({
            name:
                "Shadowsocks TCP",

            value:
                ss
        });
    }

    const subscriptionUrl =
        `${getPublicOrigin(req)}/sub/${user.subscription_token}`;

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
content="width=device-width,initial-scale=1">

<title>
${escapeHtml(user.username)}
- VergilPanel
</title>

<style>

* {
    box-sizing:
        border-box;
}

body {
    margin:
        0;

    min-height:
        100vh;

    background:
        radial-gradient(
            circle at top,
            #102b48,
            #06101d 50%,
            #03070e
        );

    color:
        #e8f5ff;

    font-family:
        Arial,
        sans-serif;
}

nav {
    height:
        70px;

    padding:
        0 25px;

    display:
        flex;

    justify-content:
        space-between;

    align-items:
        center;

    background:
        rgba(3,10,20,.7);

    border-bottom:
        1px solid
        rgba(56,189,248,.12);
}

.logo {
    color:
        #38bdf8;

    font-weight:
        900;

    font-size:
        22px;
}

nav a {
    color:
        #9fc0d5;

    text-decoration:
        none;
}

.container {
    width:
        min(1100px,94%);

    margin:
        35px auto;
}

.header {
    margin-bottom:
        25px;
}

.header h1 {
    margin-bottom:
        5px;
}

.muted {
    color:
        #678499;

    font-size:
        12px;
}

.subscription {
    padding:
        25px;

    background:
        rgba(7,20,34,.9);

    border:
        1px solid
        rgba(56,189,248,.14);

    border-radius:
        18px;

    margin-bottom:
        22px;

    text-align:
        center;
}

.subscription img {
    width:
        190px;

    height:
        190px;

    background:
        white;

    padding:
        10px;

    border-radius:
        12px;
}

.url {
    margin-top:
        20px;

    padding:
        13px;

    background:
        #030b14;

    border-radius:
        10px;

    color:
        #7dd3fc;

    word-break:
        break-all;

    font-size:
        11px;
}

.grid {
    display:
        grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(300px,1fr)
        );

    gap:
        18px;
}

.card {
    padding:
        22px;

    background:
        rgba(7,20,34,.9);

    border:
        1px solid
        rgba(56,189,248,.12);

    border-radius:
        18px;
}

.card h3 {
    margin-top:
        0;
}

.qr {
    display:
        block;

    width:
        170px;

    height:
        170px;

    margin:
        15px auto;

    padding:
        8px;

    background:
        white;

    border-radius:
        10px;
}

.link {
    padding:
        12px;

    background:
        #030b14;

    border-radius:
        9px;

    color:
        #9bdcff;

    font-size:
        10px;

    word-break:
        break-all;
}

.brand {
    margin-top:
        25px;

    padding:
        20px;

    text-align:
        center;

    color:
        #7290a4;

    background:
        rgba(7,20,34,.65);

    border-radius:
        15px;

    font-size:
        11px;
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

${configCards.map(
    card => `
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
`
).join("")}

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


// ============================================================
// Settings page
// ============================================================

function settingsPage(
    message = "",
    error = ""
) {
    const settings =
        getSettings();

    const admin =
        getAdmin();

    return `
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1">

<title>
Settings
</title>

<style>

* {
    box-sizing:
        border-box;
}

body {
    margin:
        0;

    min-height:
        100vh;

    background:
        radial-gradient(
            circle at top,
            #102b48,
            #06101d 50%,
            #03070e
        );

    color:
        #e8f5ff;

    font-family:
        Arial,
        sans-serif;
}

nav {
    height:
        70px;

    padding:
        0 25px;

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

    background:
        rgba(3,10,20,.7);

    border-bottom:
        1px solid
        rgba(56,189,248,.12);
}

.logo {
    color:
        #38bdf8;

    font-weight:
        900;

    font-size:
        22px;
}

nav a {
    color:
        #9fc0d5;

    text-decoration:
        none;
}

.container {
    width:
        min(650px,92%);

    margin:
        45px auto;
}

.card {
    padding:
        30px;

    background:
        rgba(7,20,34,.92);

    border:
        1px solid
        rgba(56,189,248,.12);

    border-radius:
        20px;
}

label {
    display:
        block;

    margin:
        18px 0 8px;

    color:
        #a3bfce;
}

input {
    width:
        100%;

    padding:
        13px;

    background:
        #071321;

    color:
        white;

    border:
        1px solid
        rgba(255,255,255,.1);

    border-radius:
        10px;

    outline:
        none;
}

input:focus {
    border-color:
        #38bdf8;
}

button {
    width:
        100%;

    padding:
        14px;

    margin-top:
        25px;

    border:
        0;

    border-radius:
        10px;

    background:
        linear-gradient(
            135deg,
            #0284c7,
            #38bdf8
        );

    color:
        white;

    font-weight:
        900;

    cursor:
        pointer;
}

.message {
    padding:
        12px;

    margin-bottom:
        15px;

    background:
        rgba(52,211,153,.1);

    color:
        #6ee7b7;

    border-radius:
        10px;
}

.error {
    padding:
        12px;

    margin-bottom:
        15px;

    background:
        rgba(239,68,68,.1);

    color:
        #fca5a5;

    border-radius:
        10px;
}

.info {
    margin-top:
        20px;

    padding:
        15px;

    border-radius:
        10px;

    background:
        rgba(56,189,248,.05);

    border:
        1px solid
        rgba(56,189,248,.1);

    color:
        #7795a8;

    font-size:
        12px;

    line-height:
        1.7;
}

code {
    color:
        #7dd3fc;
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

${
    error
        ? `<div class="error">${escapeHtml(error)}</div>`
        : ""
}

<form
method="POST"
action="/settings">

<label>
Panel Host
</label>

<input
name="panel_host"
value="${escapeHtml(
    settings?.panel_host || ""
)}"
placeholder="your-domain.up.railway.app"
required>

<label>
Railway TCP Proxy Host
</label>

<input
name="tcp_proxy_host"
value="${escapeHtml(
    settings?.tcp_proxy_host || ""
)}"
placeholder="xxxx.proxy.rlwy.net">

<label>
Railway TCP Proxy Port
</label>

<input
type="number"
name="tcp_proxy_port"
value="${escapeHtml(
    settings?.tcp_proxy_port || ""
)}"
placeholder="443">

<div class="info">

<b>
Railway setup:
</b>

<br><br>

1. Deploy the panel.

<br>

2. Generate your Railway domain.

<br>

3. Create a TCP Proxy manually in Railway.

<br>

4. Point the TCP Proxy to:
<code>10005</code>

<br>

5. Put the Railway TCP Proxy hostname and public port above.

<br><br>

Shadowsocks will then automatically use this TCP Proxy.

<br><br>

Xray itself keeps TLS disabled internally.
Railway handles HTTPS/WSS on the public side.

</div>

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

<button>
SAVE SETTINGS
</button>

</form>

</div>

</div>

</body>

</html>
`;
}


// ============================================================
// Request handler
// ============================================================

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


// ------------------------------------------------------------
// XHTTP proxy
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// Subscription
// ------------------------------------------------------------

        if (
            pathname.startsWith(
                "/sub/"
            )
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
                        error:
                            "Invalid subscription"
                    },
                    404
                );

                return;
            }

            const subscription =
                makeSubscription(
                    user,
                    req
                );

            res.writeHead(
                200,
                {
                    "Content-Type":
                        "text/plain; charset=utf-8",

                    "Cache-Control":
                        "no-store",

                    "Profile-Update-Interval":
                        "1"
                }
            );

            res.end(
                subscription
            );

            return;
        }


// ------------------------------------------------------------
// Health
// ------------------------------------------------------------

        if (
            pathname === "/health"
        ) {
            sendJson(
                res,
                {
                    ok:
                        true,

                    version:
                        VERSION,

                    xray:
                        Boolean(
                            xrayProcess
                        ),

                    users:
                        activeUsers().length,

                    tcpProxyConfigured:
                        Boolean(
                            getTcpHost() &&
                            getTcpPort()
                        )
                }
            );

            return;
        }


// ------------------------------------------------------------
// Login
// ------------------------------------------------------------

        if (
            pathname === "/login" &&
            req.method === "GET"
        ) {
            if (
                getSession(req)
            ) {
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


        if (
            pathname === "/login" &&
            req.method === "POST"
        ) {
            const form =
                await readForm(req);

            const username =
                String(
                    form.get("username") ||
                    ""
                );

            const password =
                String(
                    form.get("password") ||
                    ""
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
                    adminId:
                        admin.id,

                    username:
                        admin.username
                }
            );

            res.writeHead(
                302,
                {
                    Location:
                        "/",

                    "Set-Cookie":
                        `session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax`
                }
            );

            res.end();

            return;
        }


// ------------------------------------------------------------
// Logout
// ------------------------------------------------------------

        if (
            pathname === "/logout"
        ) {
            const cookies =
                parseCookies(req);

            if (
                cookies.session
            ) {
                sessions.delete(
                    cookies.session
                );
            }

            res.writeHead(
                302,
                {
                    Location:
                        "/login",

                    "Set-Cookie":
                        "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
                }
            );

            res.end();

            return;
        }


// ------------------------------------------------------------
// Auth
// ------------------------------------------------------------

        const session =
            requireAuth(
                req,
                res
            );

        if (!session) {
            return;
        }


// ------------------------------------------------------------
// Dashboard
// ------------------------------------------------------------

        if (
            pathname === "/" ||
            pathname === "/dashboard"
        ) {
            sendHtml(
                res,
                dashboardPage(
                    allUsers()
                )
            );

            return;
        }


// ------------------------------------------------------------
// Settings GET
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// Settings POST
// ------------------------------------------------------------

        if (
            pathname === "/settings" &&
            req.method === "POST"
        ) {
            const form =
                await readForm(req);

            const panelHost =
                String(
                    form.get("panel_host") ||
                    ""
                )
                    .trim()
                    .replace(
                        /^https?:\/\//i,
                        ""
                    )
                    .replace(
                        /\/+$/,
                        ""
                    );

            const tcpHost =
                String(
                    form.get(
                        "tcp_proxy_host"
                    ) || ""
                ).trim();

            const tcpPort =
                Number(
                    form.get(
                        "tcp_proxy_port"
                    ) || 0
                );

            const username =
                String(
                    form.get("username") ||
                    ""
                ).trim();

            const password =
                String(
                    form.get("password") ||
                    ""
                );

            if (!panelHost) {
                sendHtml(
                    res,
                    settingsPage(
                        "",
                        "Panel Host is required."
                    ),
                    400
                );

                return;
            }

            if (
                tcpHost &&
                (
                    !Number.isInteger(
                        tcpPort
                    ) ||
                    tcpPort < 1 ||
                    tcpPort > 65535
                )
            ) {
                sendHtml(
                    res,
                    settingsPage(
                        "",
                        "TCP Proxy Port is invalid."
                    ),
                    400
                );

                return;
            }

            db.prepare(`
                UPDATE settings
                SET
                    panel_host = ?,
                    tcp_proxy_host = ?,
                    tcp_proxy_port = ?,
                    updated_at = ?
                WHERE id = 1
            `).run(
                panelHost,
                tcpHost,
                tcpPort,
                nowIso()
            );

            if (!username) {
                sendHtml(
                    res,
                    settingsPage(
                        "",
                        "Admin username cannot be empty."
                    ),
                    400
                );

                return;
            }

            if (password) {
                db.prepare(`
                    UPDATE admins
                    SET
                        username = ?,
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
                    SET
                        username = ?
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


// ------------------------------------------------------------
// New user GET
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// New user POST
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// Config page
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// Toggle user
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// Delete user
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// 404
// ------------------------------------------------------------

        sendHtml(
            res,
            `
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
404
</title>

<style>

body {
    background:
        #030812;

    color:
        #38bdf8;

    font-family:
        Arial;

    text-align:
        center;

    padding-top:
        100px;
}

a {
    color:
        #38bdf8;
}

</style>

</head>

<body>

<h1>
404
</h1>

<p>
VergilPanel - Page not found.
</p>

<a href="/">
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

        if (
            !res.headersSent
        ) {
            sendJson(
                res,
                {
                    ok:
                        false,

                    error:
                        error.message
                },
                500
            );
        }
    }
}


// ============================================================
// HTTP server
// ============================================================

const server =
    http.createServer(
        handleRequest
    );


// ============================================================
// WebSocket routing
// ============================================================

server.on(
    "upgrade",
    (
        req,
        socket,
        head
    ) => {
        try {
            const pathname =
                new URL(
                    req.url,
                    `http://${req.headers.host || "localhost"}`
                ).pathname;


// ------------------------------------------------------------
// VLESS WS
// ------------------------------------------------------------

            if (
                pathname ===
                    VLESS_WS_PATH ||
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


// ------------------------------------------------------------
// VMess WS
// ------------------------------------------------------------

            if (
                pathname ===
                    VMESS_WS_PATH ||
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


// ------------------------------------------------------------
// Trojan WS
// ------------------------------------------------------------

            if (
                pathname ===
                    TROJAN_WS_PATH ||
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


// ============================================================
// Startup
// ============================================================

ensureDefaultAdmin();

await startXray();

server.listen(
    PORT,
    HOST,
    () => {
        const settings =
            getSettings();

        console.log(
            `⚔️ VergilPanel v${VERSION} running on ${HOST}:${PORT}`
        );

        console.log(
            `🌐 Panel Host: ${settings.panel_host || "auto"}`
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
            `🔌 Shadowsocks TCP: ${XRAY_SS_PORT}`
        );

        console.log(
            `🔗 TCP Proxy: ${
                settings.tcp_proxy_host
                    ? `${settings.tcp_proxy_host}:${settings.tcp_proxy_port}`
                    : "NOT CONFIGURED"
            }`
        );

        console.log(
            `💙 ${BRAND_1}`
        );

        console.log(
            `🖤 ${BRAND_2}`
        );
    }
);


// ============================================================
// Shutdown
// ============================================================

async function shutdown(
    signal
) {
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
