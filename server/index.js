const http = require("http");
const crypto = require("crypto");
const fs = require("fs/promises");
const Database = require("better-sqlite3");

const PORT = Number(process.env.PORT || 8080);
const HOST = "0.0.0.0";

const DATA_DIR = process.env.DATA_DIR || "/app/data";
const DB_PATH = `${DATA_DIR}/vergilpanel.db`;

let db;

async function ensureDataDir() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function initDatabase() {
  await ensureDataDir();

  db = new Database(DB_PATH);

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
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function generateUUID() {
  return crypto.randomUUID();
}

function nowISO() {
  return new Date().toISOString();
}

const sessions = new Map();

function createSession(adminId, username) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    adminId,
    username,
    createdAt: Date.now()
  });

  return token;
}

function deleteSession(token) {
  if (token) {
    sessions.delete(token);
  }
}

function getSessionToken(req) {
  const cookie = req.headers.cookie || "";

  const match = cookie.match(/(?:^|;\s*)vergil_session=([^;]+)/);

  return match ? match[1] : null;
}

function getSession(req) {
  const token = getSessionToken(req);

  if (!token) {
    return null;
  }

  return sessions.get(token) || null;
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk.toString();

      if (body.length > 1024 * 1024) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
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

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatUptime(seconds) {
  seconds = Math.floor(seconds);

  const days = Math.floor(seconds / 86400);
  seconds %= 86400;

  const hours = Math.floor(seconds / 3600);
  seconds %= 3600;

  const minutes = Math.floor(seconds / 60);
  seconds %= 60;

  const parts = [];

  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);

  parts.push(`${seconds}s`);

  return parts.join(" ");
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);

  if (value === 0) {
    return "Unlimited";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];

  let size = value;
  let index = 0;

  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index++;
  }

  return `${size.toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
}

function formatDate(date) {
  if (!date) {
    return "No expiry";
  }

  const d = new Date(date);

  if (Number.isNaN(d.getTime())) {
    return "Invalid date";
  }

  return d.toLocaleDateString("en-GB", {
    year: "numeric",
    month: "short",
    day: "numeric"
  });
}

function redirect(res, location) {
  res.writeHead(302, {
    Location: location
  });

  res.end();
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });

  res.end(JSON.stringify(data));
}

function sendHtml(res, statusCode, html) {
  res.writeHead(statusCode, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store"
  });

  res.end(html);
}

function page(title, content, session = null) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  >
  <title>${escapeHtml(title)} — VergilPanel</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
      background:
        radial-gradient(
          circle at top right,
          rgba(88, 28, 135, 0.22),
          transparent 35%
        ),
        #070711;
      color: #f5f5f5;
      min-height: 100vh;
    }

    a {
      color: inherit;
      text-decoration: none;
    }

    .container {
      width: min(1150px, calc(100% - 32px));
      margin: 0 auto;
    }

    .navbar {
      border-bottom: 1px solid rgba(255,255,255,0.08);
      background: rgba(7,7,17,0.82);
      backdrop-filter: blur(14px);
      position: sticky;
      top: 0;
      z-index: 10;
    }

    .nav-inner {
      min-height: 70px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
    }

    .brand {
      font-size: 21px;
      font-weight: 800;
      letter-spacing: -0.5px;
    }

    .brand span {
      color: #a855f7;
    }

    .nav-right {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }

    .admin-badge {
      padding: 8px 12px;
      border-radius: 10px;
      background: rgba(255,255,255,0.06);
      color: #cfcfe5;
      font-size: 13px;
    }

    .logout {
      border: 0;
      cursor: pointer;
      padding: 8px 13px;
      border-radius: 10px;
      background: rgba(239,68,68,0.12);
      color: #fca5a5;
      font-weight: 600;
    }

    main {
      padding: 38px 0 60px;
    }

    h1 {
      margin: 0;
      font-size: 32px;
      letter-spacing: -1px;
    }

    h2 {
      margin-top: 0;
    }

    .subtitle {
      margin-top: 8px;
      color: #9999ad;
    }

    .cards {
      display: grid;
      grid-template-columns:
        repeat(auto-fit, minmax(190px, 1fr));
      gap: 16px;
      margin-top: 28px;
    }

    .card {
      background: rgba(255,255,255,0.045);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 17px;
      padding: 20px;
      box-shadow:
        0 10px 40px rgba(0,0,0,0.18);
    }

    .card-label {
      color: #9696aa;
      font-size: 13px;
      margin-bottom: 10px;
    }

    .card-value {
      font-size: 25px;
      font-weight: 800;
    }

    .green {
      color: #4ade80;
    }

    .yellow {
      color: #facc15;
    }

    .muted {
      color: #9696aa;
    }

    .section {
      margin-top: 28px;
    }

    .section-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 16px;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      border: 0;
      cursor: pointer;
      padding: 11px 16px;
      border-radius: 11px;
      font-weight: 700;
      font-size: 14px;
    }

    .btn-primary {
      background: linear-gradient(
        135deg,
        #9333ea,
        #6d28d9
      );
      color: white;
      box-shadow:
        0 8px 25px rgba(124,58,237,0.25);
    }

    .btn-danger {
      background: rgba(239,68,68,0.12);
      color: #fca5a5;
    }

    .btn-secondary {
      background: rgba(255,255,255,0.07);
      color: #ddd;
    }

    .table-wrap {
      overflow-x: auto;
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 16px;
      background: rgba(255,255,255,0.035);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 850px;
    }

    th,
    td {
      padding: 15px 16px;
      text-align: left;
      border-bottom:
        1px solid rgba(255,255,255,0.06);
      white-space: nowrap;
    }

    th {
      color: #9696aa;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    td {
      font-size: 14px;
    }

    tr:last-child td {
      border-bottom: 0;
    }

    .status {
      display: inline-flex;
      padding: 5px 9px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
    }

    .status-active {
      background: rgba(34,197,94,0.12);
      color: #4ade80;
    }

    .status-disabled {
      background: rgba(239,68,68,0.12);
      color: #fca5a5;
    }

    .empty {
      padding: 55px 20px;
      text-align: center;
      color: #8e8ea1;
    }

    .form-card {
      max-width: 650px;
      margin: 35px auto 0;
      background: rgba(255,255,255,0.045);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 18px;
      padding: 25px;
    }

    .field {
      margin-bottom: 18px;
    }

    label {
      display: block;
      margin-bottom: 8px;
      color: #d8d8e4;
      font-size: 14px;
      font-weight: 600;
    }

    input,
    select {
      width: 100%;
      padding: 12px 13px;
      border-radius: 11px;
      border: 1px solid rgba(255,255,255,0.1);
      background: #11111d;
      color: white;
      outline: none;
      font-size: 14px;
    }

    input:focus,
    select:focus {
      border-color: #9333ea;
    }

    .help {
      margin-top: 7px;
      color: #77778b;
      font-size: 12px;
    }

    .actions {
      display: flex;
      gap: 10px;
      margin-top: 22px;
      flex-wrap: wrap;
    }

    .notice {
      padding: 13px 15px;
      border-radius: 12px;
      margin-bottom: 18px;
      font-size: 14px;
    }

    .notice-error {
      background: rgba(239,68,68,0.1);
      color: #fca5a5;
      border: 1px solid rgba(239,68,68,0.15);
    }

    footer {
      border-top: 1px solid rgba(255,255,255,0.06);
      padding: 22px 0;
      text-align: center;
      color: #666679;
      font-size: 12px;
    }

    .back {
      display: inline-block;
      margin-bottom: 22px;
      color: #a855f7;
      font-size: 14px;
      font-weight: 600;
    }

    .uuid {
      font-family: monospace;
      font-size: 12px;
      color: #aaaabd;
    }

    @media (max-width: 650px) {
      .nav-inner {
        min-height: 62px;
      }

      .admin-badge {
        display: none;
      }

      main {
        padding-top: 28px;
      }

      h1 {
        font-size: 27px;
      }

      .section-head {
        align-items: flex-start;
      }
    }
  </style>
</head>

<body>

  <nav class="navbar">
    <div class="container nav-inner">
      <a href="/dashboard" class="brand">
        ⚔️ Vergil<span>Panel</span>
      </a>

      ${
        session
          ? `
            <div class="nav-right">
              <div class="admin-badge">
                Admin: ${escapeHtml(session.username)}
              </div>

              <form method="POST" action="/logout">
                <button class="logout" type="submit">
                  Logout
                </button>
              </form>
            </div>
          `
          : ""
      }
    </div>
  </nav>

  <main>
    <div class="container">
      ${content}
    </div>
  </main>

  <footer>
    Powered by Yasin Behzad © 2026
  </footer>

</body>
</html>
`;
}

function requireSession(req, res) {
  const session = getSession(req);

  if (!session) {
    redirect(res, "/login");
    return null;
  }

  return session;
}

function renderLogin(res, error = "") {
  const content = `
    <div class="form-card">
      <h1>Welcome back 👋</h1>

      <p class="subtitle">
        Login to your VergilPanel administrator account.
      </p>

      ${
        error
          ? `
            <div class="notice notice-error">
              ${escapeHtml(error)}
            </div>
          `
          : ""
      }

      <form method="POST" action="/login">

        <div class="field">
          <label>Username</label>
          <input
            type="text"
            name="username"
            required
            autocomplete="username"
          >
        </div>

        <div class="field">
          <label>Password</label>
          <input
            type="password"
            name="password"
            required
            autocomplete="current-password"
          >
        </div>

        <button class="btn btn-primary" type="submit">
          Login
        </button>

      </form>
    </div>
  `;

  sendHtml(
    res,
    200,
    page("Login", content)
  );
}

function renderSetup(res, error = "") {
  const content = `
    <div class="form-card">
      <h1>⚔️ Setup VergilPanel</h1>

      <p class="subtitle">
        Create your first administrator account.
      </p>

      ${
        error
          ? `
            <div class="notice notice-error">
              ${escapeHtml(error)}
            </div>
          `
          : ""
      }

      <form method="POST" action="/setup">

        <div class="field">
          <label>Username</label>
          <input
            type="text"
            name="username"
            required
            autocomplete="username"
          >
        </div>

        <div class="field">
          <label>Password</label>
          <input
            type="password"
            name="password"
            required
            minlength="6"
            autocomplete="new-password"
          >
        </div>

        <button class="btn btn-primary" type="submit">
          Create Administrator
        </button>

      </form>
    </div>
  `;

  sendHtml(
    res,
    200,
    page("Setup", content)
  );
}

function renderDashboard(res, session) {
  const adminCount = db
    .prepare("SELECT COUNT(*) AS count FROM admins")
    .get().count;

  const userCount = db
    .prepare("SELECT COUNT(*) AS count FROM users")
    .get().count;

  const activeUserCount = db
    .prepare(
      "SELECT COUNT(*) AS count FROM users WHERE status = 'active'"
    )
    .get().count;

  const content = `
    <h1>Dashboard</h1>

    <p class="subtitle">
      Welcome back, ${escapeHtml(session.username)} 👋
    </p>

    <div class="cards">

      <div class="card">
        <div class="card-label">
          Panel Status
        </div>
        <div class="card-value green">
          🟢 Online
        </div>
      </div>

      <div class="card">
        <div class="card-label">
          Database
        </div>
        <div class="card-value green">
          🟢 Connected
        </div>
      </div>

      <div class="card">
        <div class="card-label">
          Xray
        </div>
        <div class="card-value yellow">
          ⚪ Not configured
        </div>
      </div>

      <div class="card">
        <div class="card-label">
          Administrators
        </div>
        <div class="card-value">
          ${adminCount}
        </div>
      </div>

      <div class="card">
        <div class="card-label">
          Users
        </div>
        <div class="card-value">
          ${userCount}
        </div>
      </div>

      <div class="card">
        <div class="card-label">
          Active Users
        </div>
        <div class="card-value green">
          ${activeUserCount}
        </div>
      </div>

      <div class="card">
        <div class="card-label">
          Uptime
        </div>
        <div class="card-value">
          ${formatUptime(
            process.uptime()
          )}
        </div>
      </div>

      <div class="card">
        <div class="card-label">
          Version
        </div>
        <div class="card-value">
          v0.4.0
        </div>
      </div>

    </div>

    <div class="section">
      <div class="section-head">
        <h2>Management</h2>
      </div>

      <div class="cards">

        <a href="/users" class="card">
          <div style="font-size:30px">👥</div>

          <h3>Users</h3>

          <p class="muted">
            Manage VPN users, UUIDs,
            traffic limits and expiry.
          </p>
        </a>

        <div class="card">
          <div style="font-size:30px">⚡</div>

          <h3>Xray</h3>

          <p class="muted">
            Xray configuration will be
            connected in a later version.
          </p>
        </div>

        <div class="card">
          <div style="font-size:30px">⚙️</div>

          <h3>Settings</h3>

          <p class="muted">
            Panel settings are coming soon.
          </p>
        </div>

      </div>
    </div>
  `;

  sendHtml(
    res,
    200,
    page("Dashboard", content, session)
  );
}

function renderUsers(res, session) {
  const users = db
    .prepare(
      `
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
      `
    )
    .all();

  let tableContent = "";

  if (users.length === 0) {
    tableContent = `
      <tr>
        <td colspan="8">
          <div class="empty">
            <div style="font-size:40px">👤</div>
            <h3>No users yet</h3>
            <p>
              Create your first VPN user
              to get started.
            </p>
          </div>
        </td>
      </tr>
    `;
  } else {
    tableContent = users
      .map(user => {
        const statusClass =
          user.status === "active"
            ? "status-active"
            : "status-disabled";

        const statusText =
          user.status === "active"
            ? "Active"
            : "Disabled";

        return `
          <tr>

            <td>
              <strong>
                ${escapeHtml(user.username)}
              </strong>
            </td>

            <td>
              <span class="uuid">
                ${escapeHtml(user.uuid)}
              </span>
            </td>

            <td>
              ${escapeHtml(
                user.protocol.toUpperCase()
              )}
            </td>

            <td>
              ${formatBytes(
                user.traffic_used_bytes
              )}
              /
              ${formatBytes(
                user.traffic_limit_bytes
              )}
            </td>

            <td>
              ${formatDate(user.expires_at)}
            </td>

            <td>
              <span class="status ${statusClass}">
                ${statusText}
              </span>
            </td>

            <td>
              ${formatDate(user.created_at)}
            </td>

            <td>
              <form
                method="POST"
                action="/users/delete"
                onsubmit="
                  return confirm(
                    'Delete this user?'
                  );
                "
              >
                <input
                  type="hidden"
                  name="id"
                  value="${user.id}"
                >

                <button
                  type="submit"
                  class="btn btn-danger"
                >
                  Delete
                </button>
              </form>
            </td>

          </tr>
        `;
      })
      .join("");
  }

  const content = `
    <a href="/dashboard" class="back">
      ← Back to Dashboard
    </a>

    <div class="section-head">
      <div>
        <h1>👥 Users</h1>

        <p class="subtitle">
          Manage your VPN users.
        </p>
      </div>

      <a
        href="/users/new"
        class="btn btn-primary"
      >
        + Add User
      </a>
    </div>

    <div class="table-wrap">

      <table>

        <thead>
          <tr>
            <th>Username</th>
            <th>UUID</th>
            <th>Protocol</th>
            <th>Traffic</th>
            <th>Expiry</th>
            <th>Status</th>
            <th>Created</th>
            <th>Action</th>
          </tr>
        </thead>

        <tbody>
          ${tableContent}
        </tbody>

      </table>

    </div>
  `;

  sendHtml(
    res,
    200,
    page("Users", content, session)
  );
}

function renderNewUser(res, session, error = "") {
  const content = `
    <a href="/users" class="back">
      ← Back to Users
    </a>

    <div class="form-card">

      <h1>➕ Add User</h1>

      <p class="subtitle">
        Create a new VPN user.
      </p>

      ${
        error
          ? `
            <div class="notice notice-error">
              ${escapeHtml(error)}
            </div>
          `
          : ""
      }

      <form method="POST" action="/users/new">

        <div class="field">
          <label>
            Username
          </label>

          <input
            type="text"
            name="username"
            required
            maxlength="50"
            placeholder="e.g. yasin"
          >
        </div>

        <div class="field">
          <label>
            Protocol
          </label>

          <select name="protocol">
            <option value="vless">
              VLESS
            </option>
          </select>
        </div>

        <div class="field">
          <label>
            Traffic Limit (GB)
          </label>

          <input
            type="number"
            name="traffic_limit_gb"
            min="0"
            step="0.1"
            value="0"
            placeholder="0 = Unlimited"
          >

          <div class="help">
            Set 0 for unlimited traffic.
          </div>
        </div>

        <div class="field">
          <label>
            Expiry Date
          </label>

          <input
            type="date"
            name="expires_at"
          >

          <div class="help">
            Leave empty for no expiration.
          </div>
        </div>

        <div class="actions">

          <button
            type="submit"
            class="btn btn-primary"
          >
            Create User
          </button>

          <a
            href="/users"
            class="btn btn-secondary"
          >
            Cancel
          </a>

        </div>

      </form>

    </div>
  `;

  sendHtml(
    res,
    200,
    page("Add User", content, session)
  );
}

async function handleRequest(req, res) {
  const url = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  );

  const pathname = url.pathname;
  const method = req.method;

  // HEALTH
  if (
    pathname === "/health" &&
    method === "GET"
  ) {
    return sendJson(res, 200, {
      ok: true,
      service: "VergilPanel",
      version: "0.4.0",
      database: "sqlite",
      uptime: process.uptime()
    });
  }

  // SETUP STATUS
  if (
    pathname === "/api/setup/status" &&
    method === "GET"
  ) {
    const count = db
      .prepare(
        "SELECT COUNT(*) AS count FROM admins"
      )
      .get().count;

    return sendJson(res, 200, {
      setupRequired: count === 0
    });
  }

  // ROOT
  if (
    pathname === "/" &&
    method === "GET"
  ) {
    const session = getSession(req);

    if (session) {
      return redirect(res, "/dashboard");
    }

    const count = db
      .prepare(
        "SELECT COUNT(*) AS count FROM admins"
      )
      .get().count;

    if (count === 0) {
      return redirect(res, "/setup");
    }

    return redirect(res, "/login");
  }

  // SETUP GET
  if (
    pathname === "/setup" &&
    method === "GET"
  ) {
    const count = db
      .prepare(
        "SELECT COUNT(*) AS count FROM admins"
      )
      .get().count;

    if (count > 0) {
      return redirect(res, "/login");
    }

    return renderSetup(res);
  }

  // SETUP POST
  if (
    pathname === "/setup" &&
    method === "POST"
  ) {
    const count = db
      .prepare(
        "SELECT COUNT(*) AS count FROM admins"
      )
      .get().count;

    if (count > 0) {
      return redirect(res, "/login");
    }

    try {
      const body = await readBody(req);

      const username =
        String(body.username || "").trim();

      const password =
        String(body.password || "");

      if (!username || !password) {
        return renderSetup(
          res,
          "Username and password are required."
        );
      }

      if (password.length < 6) {
        return renderSetup(
          res,
          "Password must be at least 6 characters."
        );
      }

      db.prepare(
        `
        INSERT INTO admins
          (username, password_hash, created_at)
        VALUES
          (?, ?, ?)
        `
      ).run(
        username,
        hashPassword(password),
        nowISO()
      );

      return redirect(res, "/login");

    } catch (error) {
      console.error(error);

      return renderSetup(
        res,
        "Unable to create administrator."
      );
    }
  }

  // LOGIN GET
  if (
    pathname === "/login" &&
    method === "GET"
  ) {
    const session = getSession(req);

    if (session) {
      return redirect(res, "/dashboard");
    }

    return renderLogin(res);
  }

  // LOGIN POST
  if (
    pathname === "/login" &&
    method === "POST"
  ) {
    try {
      const body = await readBody(req);

      const username =
        String(body.username || "").trim();

      const password =
        String(body.password || "");

      const admin = db
        .prepare(
          `
          SELECT *
          FROM admins
          WHERE username = ?
          LIMIT 1
          `
        )
        .get(username);

      if (
        !admin ||
        admin.password_hash !==
          hashPassword(password)
      ) {
        return renderLogin(
          res,
          "Invalid username or password."
        );
      }

      const token = createSession(
        admin.id,
        admin.username
      );

      res.writeHead(302, {
        Location: "/dashboard",
        "Set-Cookie":
          `vergil_session=${token}; ` +
          "HttpOnly; Path=/; SameSite=Lax"
      });

      return res.end();

    } catch (error) {
      console.error(error);

      return renderLogin(
        res,
        "Login failed."
      );
    }
  }

  // LOGOUT
  if (
    pathname === "/logout" &&
    method === "POST"
  ) {
    const token = getSessionToken(req);

    deleteSession(token);

    res.writeHead(302, {
      Location: "/login",
      "Set-Cookie":
        "vergil_session=; " +
        "HttpOnly; Path=/; Max-Age=0; SameSite=Lax"
    });

    return res.end();
  }

  // DASHBOARD
  if (
    pathname === "/dashboard" &&
    method === "GET"
  ) {
    const session = requireSession(req, res);

    if (!session) {
      return;
    }

    return renderDashboard(res, session);
  }

  // USERS
  if (
    pathname === "/users" &&
    method === "GET"
  ) {
    const session = requireSession(req, res);

    if (!session) {
      return;
    }

    return renderUsers(res, session);
  }

  // NEW USER FORM
  if (
    pathname === "/users/new" &&
    method === "GET"
  ) {
    const session = requireSession(req, res);

    if (!session) {
      return;
    }

    return renderNewUser(res, session);
  }

  // CREATE USER
  if (
    pathname === "/users/new" &&
    method === "POST"
  ) {
    const session = requireSession(req, res);

    if (!session) {
      return;
    }

    try {
      const body = await readBody(req);

      const username =
        String(body.username || "").trim();

      const protocol =
        String(body.protocol || "vless")
          .trim()
          .toLowerCase();

      const trafficLimitGB =
        Number(body.traffic_limit_gb || 0);

      const expiresInput =
        String(body.expires_at || "").trim();

      if (!username) {
        return renderNewUser(
          res,
          session,
          "Username is required."
        );
      }

      if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
        return renderNewUser(
          res,
          session,
          "Username can only contain letters, numbers, dots, underscores and hyphens."
        );
      }

      if (protocol !== "vless") {
        return renderNewUser(
          res,
          session,
          "Only VLESS is currently supported."
        );
      }

      if (
        !Number.isFinite(trafficLimitGB) ||
        trafficLimitGB < 0
      ) {
        return renderNewUser(
          res,
          session,
          "Traffic limit is invalid."
        );
      }

      if (trafficLimitGB > 10240) {
        return renderNewUser(
          res,
          session,
          "Traffic limit cannot exceed 10240 GB."
        );
      }

      let expiresAt = null;

      if (expiresInput) {
        const parsed = new Date(
          `${expiresInput}T23:59:59.999Z`
        );

        if (Number.isNaN(parsed.getTime())) {
          return renderNewUser(
            res,
            session,
            "Expiry date is invalid."
          );
        }

        expiresAt = parsed.toISOString();
      }

      const uuid = generateUUID();

      const trafficLimitBytes = Math.floor(
        trafficLimitGB *
        1024 *
        1024 *
        1024
      );

      db.prepare(
        `
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
        VALUES
          (?, ?, ?, ?, 0, ?, 'active', ?)
        `
      ).run(
        username,
        uuid,
        protocol,
        trafficLimitBytes,
        expiresAt,
        nowISO()
      );

      return redirect(res, "/users");

    } catch (error) {
      console.error(error);

      if (
        String(error.message || "")
          .toLowerCase()
          .includes("unique")
      ) {
        return renderNewUser(
          res,
          session,
          "Username already exists."
        );
      }

      return renderNewUser(
        res,
        session,
        "Unable to create user."
      );
    }
  }

  // DELETE USER
  if (
    pathname === "/users/delete" &&
    method === "POST"
  ) {
    const session = requireSession(req, res);

    if (!session) {
      return;
    }

    try {
      const body = await readBody(req);

      const id = Number(body.id);

      if (!Number.isInteger(id) || id <= 0) {
        return redirect(res, "/users");
      }

      db.prepare(
        "DELETE FROM users WHERE id = ?"
      ).run(id);

      return redirect(res, "/users");

    } catch (error) {
      console.error(error);

      return redirect(res, "/users");
    }
  }

  // 404
  return sendHtml(
    res,
    404,
    page(
      "404",
      `
        <div class="form-card">
          <h1>404</h1>

          <p class="subtitle">
            Page not found.
          </p>

          <div class="actions">
            <a
              href="/dashboard"
              class="btn btn-primary"
            >
              Back to Dashboard
            </a>
          </div>
        </div>
      `
    )
  );
}

async function start() {
  try {
    await initDatabase();

    const server = http.createServer(
      async (req, res) => {
        try {
          await handleRequest(req, res);
        } catch (error) {
          console.error(
            "Request error:",
            error
          );

          if (!res.headersSent) {
            sendHtml(
              res,
              500,
              page(
                "Server Error",
                `
                  <div class="form-card">
                    <h1>500</h1>
                    <p class="subtitle">
                      Internal server error.
                    </p>
                  </div>
                `
              )
            );
          } else {
            res.end();
          }
        }
      }
    );

    server.listen(
      PORT,
      HOST,
      () => {
        console.log(
          `⚔️ VergilPanel v0.4.0 running on ${HOST}:${PORT}`
        );

        console.log(
          `📦 Database: ${DB_PATH}`
        );
      }
    );

  } catch (error) {
    console.error(
      "Failed to start VergilPanel:",
      error
    );

    process.exit(1);
  }
}

start();
