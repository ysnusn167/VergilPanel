import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import Database from "better-sqlite3";

const PORT = Number(process.env.PORT || 8080);
const HOST = "0.0.0.0";

const DATA_DIR = process.env.DATA_DIR || "/app/data";
const DB_PATH = `${DATA_DIR}/vergilpanel.db`;
const VERSION = "0.4.0";

await fs.mkdir(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    uuid TEXT NOT NULL UNIQUE,
    protocol TEXT NOT NULL DEFAULT 'vless',
    traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
    traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
  );
`);

const sessions = new Map();

const startedAt = Date.now();

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatUptime(ms) {
  const totalSeconds = Math.floor(ms / 1000);

  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (days > 0) {
    return `${days}d ${hours}h ${minutes}m`;
  }

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  }

  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }

  return `${seconds}s`;
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);

  if (value === 0) {
    return "Unlimited";
  }

  if (value < 1024 ** 3) {
    return `${(value / 1024 ** 2).toFixed(1)} MB`;
  }

  return `${(value / 1024 ** 3).toFixed(2)} GB`;
}

function formatDate(date) {
  if (!date) {
    return "—";
  }

  return new Date(date).toLocaleDateString("en-GB");
}

function send(res, statusCode, body, contentType = "text/html; charset=utf-8") {
  res.writeHead(statusCode, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
  });

  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, {
    Location: location,
    "Cache-Control": "no-store",
  });

  res.end();
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...parts] = cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(parts.join("="));
    }
  }

  return null;
}

function createSession(username) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    username,
    createdAt: Date.now(),
  });

  return token;
}

function getSession(req) {
  const token = getCookie(req, "vergil_session");

  if (!token) {
    return null;
  }

  return sessions.get(token) || null;
}

function deleteSession(req) {
  const token = getCookie(req, "vergil_session");

  if (token) {
    sessions.delete(token);
  }
}

function requireAuth(req, res) {
  const session = getSession(req);

  if (!session) {
    redirect(res, "/login");
    return null;
  }

  return session;
}

async function readBody(req) {
  return await new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk.toString();
    });

    req.on("end", () => {
      try {
        const contentType = req.headers["content-type"] || "";

        if (contentType.includes("application/json")) {
          resolve(body ? JSON.parse(body) : {});
          return;
        }

        if (
          contentType.includes(
            "application/x-www-form-urlencoded"
          )
        ) {
          const params = new URLSearchParams(body);

          const result = {};

          for (const [key, value] of params.entries()) {
            result[key] = value;
          }

          resolve(result);
          return;
        }

        resolve({});
      } catch (error) {
        reject(error);
      }
    });

    req.on("error", reject);
  });
}

function page(title, content, username = null) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - VergilPanel</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;

      background:
        radial-gradient(
          circle at top,
          #18223b 0,
          #090d17 45%,
          #05070d 100%
        );

      color: #f5f7ff;
      min-height: 100vh;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    .container {
      width: min(1100px, calc(100% - 32px));
      margin: 0 auto;
    }

    .nav {
      padding: 22px 0;
      border-bottom: 1px solid rgba(255,255,255,.08);
    }

    .nav-inner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
    }

    .brand {
      font-size: 21px;
      font-weight: 800;
      letter-spacing: -.5px;
    }

    .brand span {
      color: #8da2ff;
    }

    .nav-right {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }

    .admin {
      color: #aeb8d3;
      font-size: 14px;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 0;
      border-radius: 10px;
      padding: 11px 16px;
      font-size: 14px;
      font-weight: 700;
      cursor: pointer;
      color: white;
      background: #536dfe;
      transition: .2s;
    }

    .btn:hover {
      transform: translateY(-1px);
      filter: brightness(1.08);
    }

    .btn.secondary {
      background: rgba(255,255,255,.08);
    }

    .btn.danger {
      background: #d9445c;
    }

    .hero {
      padding: 42px 0 28px;
    }

    .hero h1 {
      margin: 0 0 8px;
      font-size: clamp(28px, 5vw, 42px);
      letter-spacing: -1px;
    }

    .hero p {
      margin: 0;
      color: #99a4c0;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
    }

    .card {
      background: rgba(15,21,36,.82);
      border: 1px solid rgba(255,255,255,.08);
      border-radius: 16px;
      padding: 22px;
      box-shadow: 0 12px 35px rgba(0,0,0,.2);
    }

    .card-title {
      color: #8f9ab7;
      font-size: 13px;
      margin-bottom: 12px;
    }

    .card-value {
      font-size: 25px;
      font-weight: 800;
    }

    .status {
      display: inline-flex;
      align-items: center;
      gap: 7px;
    }

    .dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: #36d399;
      display: inline-block;
    }

    .dot.off {
      background: #8a93a8;
    }

    .section {
      margin-top: 24px;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 15px;
      margin-bottom: 16px;
    }

    .section-header h2 {
      margin: 0;
      font-size: 21px;
    }

    .table-wrap {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 720px;
    }

    th,
    td {
      text-align: left;
      padding: 15px 12px;
      border-bottom: 1px solid rgba(255,255,255,.07);
    }

    th {
      color: #8e99b5;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: .5px;
    }

    td {
      color: #dce2f1;
      font-size: 14px;
    }

    .badge {
      display: inline-flex;
      padding: 5px 9px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
    }

    .badge.active {
      background: rgba(54,211,153,.12);
      color: #63e6b1;
    }

    .badge.disabled {
      background: rgba(217,68,92,.12);
      color: #ff7f91;
    }

    .form-card {
      max-width: 620px;
      margin: 45px auto;
    }

    label {
      display: block;
      margin-bottom: 7px;
      color: #b5bfd6;
      font-size: 14px;
      font-weight: 600;
    }

    input,
    select {
      width: 100%;
      padding: 13px 14px;
      border-radius: 10px;
      border: 1px solid rgba(255,255,255,.1);
      background: #0b101d;
      color: white;
      outline: none;
      margin-bottom: 18px;
      font-size: 14px;
    }

    input:focus,
    select:focus {
      border-color: #536dfe;
    }

    .login-card {
      max-width: 430px;
      margin: 90px auto;
    }

    .login-logo {
      text-align: center;
      font-size: 32px;
      font-weight: 900;
      margin-bottom: 8px;
    }

    .login-subtitle {
      text-align: center;
      color: #8f9ab7;
      margin-bottom: 28px;
    }

    .error {
      background: rgba(217,68,92,.12);
      border: 1px solid rgba(217,68,92,.25);
      color: #ff8b9a;
      padding: 12px 14px;
      border-radius: 10px;
      margin-bottom: 18px;
      font-size: 14px;
    }

    footer {
      padding: 45px 0 30px;
      text-align: center;
      color: #66718d;
      font-size: 12px;
    }

    .empty {
      text-align: center;
      padding: 45px 20px;
      color: #7e89a5;
    }

    .actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    @media (max-width: 850px) {
      .grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 560px) {
      .grid {
        grid-template-columns: 1fr;
      }

      .nav-inner {
        align-items: flex-start;
        flex-direction: column;
      }

      .hero {
        padding-top: 30px;
      }
    }
  </style>
</head>

<body>

  ${
    username
      ? `
  <nav class="nav">
    <div class="container nav-inner">
      <a href="/dashboard" class="brand">
        ⚔️ Vergil<span>Panel</span>
      </a>

      <div class="nav-right">
        <span class="admin">
          Admin: ${escapeHtml(username)}
        </span>

        <a href="/dashboard" class="btn secondary">
          Dashboard
        </a>

        <form method="POST" action="/logout" style="margin:0;">
          <button class="btn danger" type="submit">
            Logout
          </button>
        </form>
      </div>
    </div>
  </nav>
  `
      : ""
  }

  <main class="container">
    ${content}
  </main>

  <footer>
    Powered by Yasin Behzad © 2026
  </footer>

</body>
</html>`;
}

function loginPage(error = "") {
  return page(
    "Login",
    `
    <div class="card login-card">

      <div class="login-logo">
        ⚔️ VergilPanel
      </div>

      <div class="login-subtitle">
        Administrator Login
      </div>

      ${
        error
          ? `<div class="error">${escapeHtml(error)}</div>`
          : ""
      }

      <form method="POST" action="/login">

        <label>Username</label>
        <input
          type="text"
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

        <button class="btn" type="submit" style="width:100%;">
          Login
        </button>

      </form>

    </div>
    `
  );
}

function setupPage(error = "") {
  return page(
    "Setup",
    `
    <div class="card login-card">

      <div class="login-logo">
        ⚔️ VergilPanel
      </div>

      <div class="login-subtitle">
        Initial Setup
      </div>

      ${
        error
          ? `<div class="error">${escapeHtml(error)}</div>`
          : ""
      }

      <form method="POST" action="/setup">

        <label>Admin Username</label>
        <input
          type="text"
          name="username"
          autocomplete="username"
          required
        >

        <label>Admin Password</label>
        <input
          type="password"
          name="password"
          autocomplete="new-password"
          required
        >

        <button class="btn" type="submit" style="width:100%;">
          Create Administrator
        </button>

      </form>

    </div>
    `
  );
}

function dashboardPage(username) {
  const totalUsers = db
    .prepare("SELECT COUNT(*) AS count FROM users")
    .get().count;

  const activeUsers = db
    .prepare(
      "SELECT COUNT(*) AS count FROM users WHERE status = 'active'"
    )
    .get().count;

  const totalAdmins = db
    .prepare("SELECT COUNT(*) AS count FROM admins")
    .get().count;

  return page(
    "Dashboard",
    `
    <div class="hero">
      <h1>Dashboard</h1>
      <p>
        Welcome back, ${escapeHtml(username)} 👋
      </p>
    </div>

    <div class="grid">

      <div class="card">
        <div class="card-title">
          Panel Status
        </div>

        <div class="card-value status">
          <span class="dot"></span>
          Online
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          Database
        </div>

        <div class="card-value status">
          <span class="dot"></span>
          Connected
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          Users
        </div>

        <div class="card-value">
          ${totalUsers}
        </div>
      </div>

      <div class="card">
        <div class="card-title">
          Active Users
        </div>

        <div class="card-value">
          ${activeUsers}
        </div>
      </div>

    </div>

    <div class="section">

      <div class="section-header">
        <h2>System</h2>
      </div>

      <div class="grid">

        <div class="card">
          <div class="card-title">
            Administrators
          </div>

          <div class="card-value">
            ${totalAdmins}
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            Xray
          </div>

          <div class="card-value status">
            <span class="dot off"></span>
            Not configured
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            Uptime
          </div>

          <div class="card-value">
            ${formatUptime(Date.now() - startedAt)}
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            Version
          </div>

          <div class="card-value">
            v${VERSION}
          </div>
        </div>

      </div>

    </div>

    <div class="section">

      <div class="section-header">
        <h2>Management</h2>

        <a href="/users/new" class="btn">
          + New User
        </a>
      </div>

      <div class="grid">

        <a href="/users" class="card">
          <div class="card-title">
            Users
          </div>

          <div class="card-value">
            Manage →
          </div>
        </a>

        <div class="card">
          <div class="card-title">
            Xray
          </div>

          <div class="card-value">
            Coming soon
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            Settings
          </div>

          <div class="card-value">
            Coming soon
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            API
          </div>

          <div class="card-value">
            Coming soon
          </div>
        </div>

      </div>

    </div>
    `,
    username
  );
}

function usersPage(username) {
  const users = db
    .prepare(`
      SELECT
        id,
        username,
        uuid,
        protocol,
        traffic_limit_bytes,
        traffic_used_bytes,
        expires_at,
        status,
        created_at
      FROM users
      ORDER BY id DESC
    `)
    .all();

  const rows = users.length
    ? users
        .map(
          (user) => `
      <tr>

        <td>
          <strong>${escapeHtml(user.username)}</strong>
        </td>

        <td>
          ${escapeHtml(user.protocol.toUpperCase())}
        </td>

        <td style="font-family:monospace;font-size:12px;">
          ${escapeHtml(user.uuid)}
        </td>

        <td>
          ${formatBytes(user.traffic_limit_bytes)}
        </td>

        <td>
          ${formatBytes(user.traffic_used_bytes)}
        </td>

        <td>
          ${formatDate(user.expires_at)}
        </td>

        <td>
          <span class="badge ${
            user.status === "active"
              ? "active"
              : "disabled"
          }">
            ${escapeHtml(user.status)}
          </span>
        </td>

        <td>
          <form method="POST" action="/users/delete">
            <input
              type="hidden"
              name="id"
              value="${user.id}"
            >

            <button
              class="btn danger"
              type="submit"
              onclick="return confirm('Delete this user?')"
            >
              Delete
            </button>
          </form>
        </td>

      </tr>
    `
        )
        .join("")
    : `
      <tr>
        <td colspan="8">
          <div class="empty">
            No users yet.
          </div>
        </td>
      </tr>
    `;

  return page(
    "Users",
    `
    <div class="hero">

      <h1>Users</h1>

      <p>
        Manage your VLESS users.
      </p>

    </div>

    <div class="card">

      <div class="section-header">

        <h2>User Management</h2>

        <div class="actions">

          <a
            href="/dashboard"
            class="btn secondary"
          >
            Dashboard
          </a>

          <a
            href="/users/new"
            class="btn"
          >
            + New User
          </a>

        </div>

      </div>

      <div class="table-wrap">

        <table>

          <thead>
            <tr>
              <th>Username</th>
              <th>Protocol</th>
              <th>UUID</th>
              <th>Limit</th>
              <th>Used</th>
              <th>Expires</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            ${rows}
          </tbody>

        </table>

      </div>

    </div>
    `,
    username
  );
}

function newUserPage(username, error = "") {
  return page(
    "New User",
    `
    <div class="hero">
      <h1>New User</h1>
      <p>Create a new VLESS user.</p>
    </div>

    <div class="card form-card">

      ${
        error
          ? `<div class="error">${escapeHtml(error)}</div>`
          : ""
      }

      <form method="POST" action="/users/new">

        <label>
          Username
        </label>

        <input
          type="text"
          name="username"
          placeholder="e.g. user01"
          required
        >

        <label>
          Protocol
        </label>

        <select name="protocol">
          <option value="vless">
            VLESS
          </option>
        </select>

        <label>
          Traffic Limit (GB)
        </label>

        <input
          type="number"
          name="traffic_limit_gb"
          min="0"
          step="0.1"
          value="0"
        >

        <small style="display:block;color:#77829e;margin-top:-10px;margin-bottom:18px;">
          0 = Unlimited
        </small>

        <label>
          Expiry Date
        </label>

        <input
          type="date"
          name="expires_at"
        >

        <div class="actions">

          <button
            class="btn"
            type="submit"
          >
            Create User
          </button>

          <a
            href="/users"
            class="btn secondary"
          >
            Cancel
          </a>

        </div>

      </form>

    </div>
    `,
    username
  );
}

async function handleRequest(req, res) {
  const url = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  );

  const path = url.pathname;
  const method = req.method;

  /*
   * HEALTH
   */
  if (method === "GET" && path === "/health") {
    send(
      res,
      200,
      JSON.stringify(
        {
          ok: true,
          service: "VergilPanel",
          version: VERSION,
          database: "sqlite",
        },
        null,
        2
      ),
      "application/json; charset=utf-8"
    );

    return;
  }

  /*
   * SETUP STATUS
   */
  if (method === "GET" && path === "/api/setup/status") {
    const admin = db
      .prepare("SELECT id FROM admins LIMIT 1")
      .get();

    send(
      res,
      200,
      JSON.stringify({
        setupRequired: !admin,
      }),
      "application/json; charset=utf-8"
    );

    return;
  }

  /*
   * ROOT
   */
  if (method === "GET" && path === "/") {
    const admin = db
      .prepare("SELECT id FROM admins LIMIT 1")
      .get();

    if (!admin) {
      redirect(res, "/setup");
      return;
    }

    const session = getSession(req);

    if (session) {
      redirect(res, "/dashboard");
      return;
    }

    redirect(res, "/login");
    return;
  }

  /*
   * SETUP GET
   */
  if (method === "GET" && path === "/setup") {
    const admin = db
      .prepare("SELECT id FROM admins LIMIT 1")
      .get();

    if (admin) {
      redirect(res, "/login");
      return;
    }

    send(res, 200, setupPage());
    return;
  }

  /*
   * SETUP POST
   */
  if (method === "POST" && path === "/setup") {
    const admin = db
      .prepare("SELECT id FROM admins LIMIT 1")
      .get();

    if (admin) {
      redirect(res, "/login");
      return;
    }

    try {
      const body = await readBody(req);

      const username = String(body.username || "").trim();
      const password = String(body.password || "");

      if (!username || !password) {
        send(
          res,
          400,
          setupPage("Username and password are required.")
        );

        return;
      }

      if (password.length < 6) {
        send(
          res,
          400,
          setupPage(
            "Password must be at least 6 characters."
          )
        );

        return;
      }

      db.prepare(`
        INSERT INTO admins
        (username, password_hash, created_at)
        VALUES (?, ?, ?)
      `).run(
        username,
        hashPassword(password),
        new Date().toISOString()
      );

      redirect(res, "/login");
      return;
    } catch (error) {
      console.error(error);

      send(
        res,
        500,
        setupPage("Unable to complete setup.")
      );

      return;
    }
  }

  /*
   * LOGIN GET
   */
  if (method === "GET" && path === "/login") {
    const admin = db
      .prepare("SELECT id FROM admins LIMIT 1")
      .get();

    if (!admin) {
      redirect(res, "/setup");
      return;
    }

    const session = getSession(req);

    if (session) {
      redirect(res, "/dashboard");
      return;
    }

    send(res, 200, loginPage());
    return;
  }

  /*
   * LOGIN POST
   */
  if (method === "POST" && path === "/login") {
    try {
      const body = await readBody(req);

      const username = String(body.username || "").trim();
      const password = String(body.password || "");

      const admin = db
        .prepare(`
          SELECT *
          FROM admins
          WHERE username = ?
          LIMIT 1
        `)
        .get(username);

      if (
        !admin ||
        admin.password_hash !== hashPassword(password)
      ) {
        send(
          res,
          401,
          loginPage("Invalid username or password.")
        );

        return;
      }

      const token = createSession(username);

      res.writeHead(302, {
        Location: "/dashboard",
        "Set-Cookie": [
          `vergil_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax`,
        ],
        "Cache-Control": "no-store",
      });

      res.end();

      return;
    } catch (error) {
      console.error(error);

      send(
        res,
        500,
        loginPage("Login failed.")
      );

      return;
    }
  }

  /*
   * LOGOUT
   */
  if (method === "POST" && path === "/logout") {
    deleteSession(req);

    res.writeHead(302, {
      Location: "/login",
      "Set-Cookie":
        "vergil_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax",
      "Cache-Control": "no-store",
    });

    res.end();

    return;
  }

  /*
   * DASHBOARD
   */
  if (method === "GET" && path === "/dashboard") {
    const session = requireAuth(req, res);

    if (!session) {
      return;
    }

    send(
      res,
      200,
      dashboardPage(session.username)
    );

    return;
  }

  /*
   * USERS
   */
  if (method === "GET" && path === "/users") {
    const session = requireAuth(req, res);

    if (!session) {
      return;
    }

    send(
      res,
      200,
      usersPage(session.username)
    );

    return;
  }

  /*
   * NEW USER GET
   */
  if (method === "GET" && path === "/users/new") {
    const session = requireAuth(req, res);

    if (!session) {
      return;
    }

    send(
      res,
      200,
      newUserPage(session.username)
    );

    return;
  }

  /*
   * NEW USER POST
   */
  if (method === "POST" && path === "/users/new") {
    const session = requireAuth(req, res);

    if (!session) {
      return;
    }

    try {
      const body = await readBody(req);

      const username = String(body.username || "").trim();
      const protocol = String(
        body.protocol || "vless"
      ).toLowerCase();

      const trafficLimitGb = Number(
        body.traffic_limit_gb || 0
      );

      const expiresAtRaw = String(
        body.expires_at || ""
      ).trim();

      if (!username) {
        send(
          res,
          400,
          newUserPage(
            session.username,
            "Username is required."
          )
        );

        return;
      }

      if (protocol !== "vless") {
        send(
          res,
          400,
          newUserPage(
            session.username,
            "Only VLESS is currently supported."
          )
        );

        return;
      }

      if (
        !Number.isFinite(trafficLimitGb) ||
        trafficLimitGb < 0
      ) {
        send(
          res,
          400,
          newUserPage(
            session.username,
            "Traffic limit is invalid."
          )
        );

        return;
      }

      const existing = db
        .prepare(`
          SELECT id
          FROM users
          WHERE username = ?
          LIMIT 1
        `)
        .get(username);

      if (existing) {
        send(
          res,
          400,
          newUserPage(
            session.username,
            "This username already exists."
          )
        );

        return;
      }

      const uuid = crypto.randomUUID();

      const trafficLimitBytes = Math.floor(
        trafficLimitGb * 1024 ** 3
      );

      const expiresAt = expiresAtRaw
        ? new Date(
            `${expiresAtRaw}T23:59:59.000Z`
          ).toISOString()
        : null;

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
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        username,
        uuid,
        protocol,
        trafficLimitBytes,
        0,
        expiresAt,
        "active",
        new Date().toISOString()
      );

      redirect(res, "/users");
      return;
    } catch (error) {
      console.error(error);

      send(
        res,
        500,
        newUserPage(
          session.username,
          "Unable to create user."
        )
      );

      return;
    }
  }

  /*
   * DELETE USER
   */
  if (
    method === "POST" &&
    path === "/users/delete"
  ) {
    const session = requireAuth(req, res);

    if (!session) {
      return;
    }

    try {
      const body = await readBody(req);

      const id = Number(body.id);

      if (!Number.isInteger(id)) {
        redirect(res, "/users");
        return;
      }

      db.prepare(
        "DELETE FROM users WHERE id = ?"
      ).run(id);

      redirect(res, "/users");
      return;
    } catch (error) {
      console.error(error);

      send(
        res,
        500,
        "Unable to delete user."
      );

      return;
    }
  }

  /*
   * 404
   */
  send(
    res,
    404,
    page(
      "404",
      `
      <div class="hero">
        <h1>404</h1>
        <p>
          The page you are looking for does not exist.
        </p>
      </div>

      <a href="/" class="btn">
        Go Home
      </a>
      `
    )
  );
}

const server = http.createServer(
  async (req, res) => {
    try {
      await handleRequest(req, res);
    } catch (error) {
      console.error("Unhandled server error:", error);

      if (!res.headersSent) {
        send(
          res,
          500,
          "Internal Server Error"
        );
      } else {
        res.end();
      }
    }
  }
);

server.listen(PORT, HOST, () => {
  console.log(
    `⚔️ VergilPanel v${VERSION} running on ${HOST}:${PORT}`
  );

  console.log(
    `📦 Database: ${DB_PATH}`
  );
});
