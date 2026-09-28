import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import Database from "better-sqlite3";

const PORT = Number(process.env.PORT) || 8080;
const HOST = "0.0.0.0";

const DATA_DIR = process.env.DATA_DIR || "/app/data";
const DB_PATH = `${DATA_DIR}/vergilpanel.db`;

const START_TIME = Date.now();

await fs.mkdir(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);


// ======================================================
// SESSION SYSTEM
// ======================================================

const sessions = new Map();

function createSession(admin) {
  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    adminId: admin.id,
    username: admin.username,
    createdAt: Date.now()
  });

  return token;
}

function deleteSession(token) {
  if (token) {
    sessions.delete(token);
  }
}

function getSession(req) {
  const cookieHeader = req.headers.cookie || "";

  const cookies = {};

  for (const part of cookieHeader.split(";")) {
    const [key, ...valueParts] = part.trim().split("=");

    if (!key) continue;

    cookies[key] = valueParts.join("=");
  }

  const token = cookies.vergil_session;

  if (!token) {
    return null;
  }

  return sessions.get(token) || null;
}

function getSessionToken(req) {
  const cookieHeader = req.headers.cookie || "";

  for (const part of cookieHeader.split(";")) {
    const [key, ...valueParts] = part.trim().split("=");

    if (key === "vergil_session") {
      return valueParts.join("=");
    }
  }

  return null;
}


// ======================================================
// PASSWORD
// ======================================================

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}


// ======================================================
// RESPONSE HELPERS
// ======================================================

function sendHtml(res, status, html, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    ...headers
  });

  res.end(html);
}

function sendJson(res, status, data, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    ...headers
  });

  res.end(JSON.stringify(data));
}


// ======================================================
// BODY PARSER
// ======================================================

async function readBody(req) {
  let body = "";

  for await (const chunk of req) {
    body += chunk;
  }

  const contentType = String(
    req.headers["content-type"] || ""
  ).toLowerCase();

  // JSON
  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(body);
    } catch {
      return null;
    }
  }

  // HTML Form
  if (
    contentType.includes(
      "application/x-www-form-urlencoded"
    )
  ) {
    try {
      const params = new URLSearchParams(body);

      return {
        username: params.get("username") || "",
        password: params.get("password") || ""
      };
    } catch {
      return null;
    }
  }

  // Fallback
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}


// ======================================================
// HTML ESCAPE
// ======================================================

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


// ======================================================
// TIME
// ======================================================

function formatUptime() {
  const seconds = Math.floor(
    (Date.now() - START_TIME) / 1000
  );

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (days > 0) {
    return `${days}d ${hours}h ${minutes}m`;
  }

  if (hours > 0) {
    return `${hours}h ${minutes}m ${secs}s`;
  }

  if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }

  return `${secs}s`;
}


// ======================================================
// PAGE TEMPLATE
// ======================================================

function page(title, content) {
  return `
<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="UTF-8">

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  >

  <title>
    ${escapeHtml(title)} - VergilPanel
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
          #18213d 0%,
          #0b1020 45%,
          #070b16 100%
        );

      color: white;

      font-family:
        Arial,
        Helvetica,
        sans-serif;
    }

    .container {
      width: 100%;
      max-width: 1100px;

      margin: 0 auto;

      padding: 30px 20px 80px;
    }

    .box {
      width: 100%;
      max-width: 420px;

      margin: 60px auto;

      background: rgba(21, 28, 50, .96);

      padding: 30px;

      border-radius: 20px;

      box-shadow:
        0 20px 60px rgba(0, 0, 0, .45);

      border:
        1px solid rgba(255,255,255,.05);
    }

    .logo {
      text-align: center;

      font-size: 30px;

      font-weight: bold;

      margin-bottom: 10px;
    }

    h1 {
      margin-top: 0;

      text-align: center;
    }

    p {
      color: #aab3cc;

      text-align: center;

      line-height: 1.6;
    }

    input {
      width: 100%;

      padding: 14px;

      margin: 8px 0;

      border:
        1px solid #303b5c;

      border-radius: 10px;

      background: #0e1426;

      color: white;

      font-size: 16px;

      outline: none;
    }

    input:focus {
      border-color: #5865f2;
    }

    button {
      width: 100%;

      padding: 14px;

      margin-top: 12px;

      border: 0;

      border-radius: 10px;

      background: #5865f2;

      color: white;

      font-size: 16px;

      font-weight: bold;

      cursor: pointer;
    }

    button:hover {
      opacity: .9;
    }

    .logout {
      background: #2b334d;
    }

    .error {
      color: #ff7070;

      text-align: center;

      margin-top: 15px;
    }

    .success {
      color: #65e6a2;

      text-align: center;

      margin-top: 15px;
    }

    .footer {
      position: fixed;

      bottom: 18px;

      left: 0;

      width: 100%;

      text-align: center;

      color: #65708d;

      font-size: 13px;
    }

    .footer span {
      color: #8d98b5;
    }

    /* Dashboard */

    .topbar {
      display: flex;

      align-items: center;

      justify-content: space-between;

      gap: 20px;

      margin-bottom: 30px;
    }

    .brand {
      font-size: 28px;

      font-weight: bold;
    }

    .admin {
      color: #9da8c2;

      font-size: 14px;
    }

    .grid {
      display: grid;

      grid-template-columns:
        repeat(
          auto-fit,
          minmax(220px, 1fr)
        );

      gap: 18px;
    }

    .card {
      background:
        rgba(21, 28, 50, .95);

      border:
        1px solid rgba(255,255,255,.05);

      border-radius: 18px;

      padding: 22px;

      box-shadow:
        0 15px 40px rgba(0,0,0,.25);
    }

    .card-title {
      color: #8f9ab5;

      font-size: 14px;

      margin-bottom: 12px;
    }

    .card-value {
      font-size: 22px;

      font-weight: bold;
    }

    .online {
      color: #65e6a2;
    }

    .offline {
      color: #ff7070;
    }

    .neutral {
      color: #aab3cc;
    }

    .welcome {
      margin-bottom: 30px;

      text-align: left;
    }

    .welcome h1 {
      text-align: left;

      margin-bottom: 8px;
    }

    .welcome p {
      text-align: left;

      margin-top: 0;
    }

    .actions {
      margin-top: 25px;

      display: grid;

      grid-template-columns:
        repeat(
          auto-fit,
          minmax(180px, 1fr)
        );

      gap: 15px;
    }

    .action {
      display: block;

      text-decoration: none;

      text-align: center;

      padding: 18px;

      border-radius: 14px;

      background: #151c32;

      color: white;

      border:
        1px solid rgba(255,255,255,.05);
    }

    .action:hover {
      background: #1b2540;
    }

    @media (max-width: 600px) {

      .container {
        padding-top: 20px;
      }

      .topbar {
        align-items: flex-start;

        flex-direction: column;
      }

      .brand {
        font-size: 24px;
      }

    }

  </style>

</head>

<body>

${content}

</body>

</html>
`;
}


// ======================================================
// FOOTER
// ======================================================

function footer() {
  return `
    <div class="footer">
      Powered by
      <span>Yasin Behzad</span>
      © 2026
    </div>
  `;
}


// ======================================================
// SERVER
// ======================================================

const server = http.createServer(
  async (req, res) => {

    try {

      const url = new URL(
        req.url || "/",
        `http://${req.headers.host || "localhost"}`
      );

      const path = url.pathname;

      // ==================================================
      // HEALTH
      // ==================================================

      if (
        req.method === "GET" &&
        path === "/health"
      ) {

        return sendJson(res, 200, {

          ok: true,

          service: "VergilPanel",

          version: "0.3.1",

          database: "sqlite",

          uptime: formatUptime()

        });

      }


      // ==================================================
      // SETUP STATUS
      // ==================================================

      if (
        req.method === "GET" &&
        path === "/api/setup/status"
      ) {

        const admin = db
          .prepare(
            "SELECT COUNT(*) AS count FROM admins"
          )
          .get();

        return sendJson(res, 200, {

          setupRequired:
            admin.count === 0

        });

      }


      // ==================================================
      // SETUP PAGE
      // ==================================================

      if (
        req.method === "GET" &&
        path === "/setup"
      ) {

        const admin = db
          .prepare(
            "SELECT COUNT(*) AS count FROM admins"
          )
          .get();

        if (admin.count > 0) {

          return sendHtml(
            res,
            302,
            "",
            {
              Location: "/login"
            }
          );

        }

        return sendHtml(
          res,
          200,

          page(
            "Setup",

            `

            <div class="box">

              <div class="logo">
                ⚔️ VergilPanel
              </div>

              <h1>
                Initial Setup
              </h1>

              <p>
                Create your administrator account.
              </p>

              <form
                method="POST"
                action="/setup"
              >

                <input
                  type="text"
                  name="username"
                  placeholder="Username"
                  required
                  minlength="3"
                  autocomplete="username"
                >

                <input
                  type="password"
                  name="password"
                  placeholder="Password"
                  required
                  minlength="6"
                  autocomplete="new-password"
                >

                <button type="submit">
                  Create Admin
                </button>

              </form>

            </div>

            ${footer()}

            `
          )

        );

      }


      // ==================================================
      // SETUP SUBMIT
      // ==================================================

      if (
        req.method === "POST" &&
        path === "/setup"
      ) {

        const body = await readBody(req);

        if (
          !body ||
          typeof body.username !== "string" ||
          typeof body.password !== "string"
        ) {

          return sendJson(
            res,
            400,
            {
              ok: false,
              error:
                "Username and password are required."
            }
          );

        }

        const username =
          body.username.trim();

        const password =
          body.password;

        if (
          username.length < 3 ||
          password.length < 6
        ) {

          return sendJson(
            res,
            400,
            {
              ok: false,
              error:
                "Username must be 3+ characters and password 6+ characters."
            }
          );

        }

        const existing = db
          .prepare(
            "SELECT COUNT(*) AS count FROM admins"
          )
          .get();

        if (existing.count > 0) {

          return sendJson(
            res,
            409,
            {
              ok: false,
              error:
                "Setup has already been completed."
            }
          );

        }

        const passwordHash =
          hashPassword(password);

        const result = db
          .prepare(`
            INSERT INTO admins
            (
              username,
              password_hash,
              created_at
            )
            VALUES (?, ?, ?)
          `)
          .run(
            username,
            passwordHash,
            new Date().toISOString()
          );

        const admin = db
          .prepare(
            "SELECT * FROM admins WHERE id = ?"
          )
          .get(result.lastInsertRowid);

        const token =
          createSession(admin);

        const secure =
          req.headers["x-forwarded-proto"] === "https"
            ? "; Secure"
            : "";

        return sendHtml(
          res,
          200,

          page(
            "Setup Complete",

            `

            <div class="box">

              <div class="logo">
                ⚔️ VergilPanel
              </div>

              <h1>
                Setup Complete
              </h1>

              <p class="success">
                Admin account created successfully.
              </p>

              <button
                onclick="location.href='/dashboard'"
              >
                Open Dashboard
              </button>

            </div>

            ${footer()}

            `
          ),

          {
            "Set-Cookie":
              `vergil_session=${token}; HttpOnly; Path=/; SameSite=Lax${secure}`
          }

        );

      }


      // ==================================================
      // LOGIN PAGE
      // ==================================================

      if (
        req.method === "GET" &&
        path === "/login"
      ) {

        const session =
          getSession(req);

        if (session) {

          return sendHtml(
            res,
            302,
            "",
            {
              Location: "/dashboard"
            }
          );

        }

        return sendHtml(
          res,
          200,

          page(
            "Login",

            `

            <div class="box">

              <div class="logo">
                ⚔️ VergilPanel
              </div>

              <h1>
                Login
              </h1>

              <p>
                Sign in to your panel.
              </p>

              <form
                method="POST"
                action="/login"
              >

                <input
                  type="text"
                  name="username"
                  placeholder="Username"
                  required
                  autocomplete="username"
                >

                <input
                  type="password"
                  name="password"
                  placeholder="Password"
                  required
                  autocomplete="current-password"
                >

                <button type="submit">
                  Login
                </button>

              </form>

            </div>

            ${footer()}

            `
          )

        );

      }


      // ==================================================
      // LOGIN SUBMIT
      // ==================================================

      if (
        req.method === "POST" &&
        path === "/login"
      ) {

        const body =
          await readBody(req);

        if (!body) {

          return sendJson(
            res,
            400,
            {
              ok: false,
              error: "Invalid request."
            }
          );

        }

        const username =
          String(
            body.username || ""
          ).trim();

        const password =
          String(
            body.password || ""
          );

        const admin =
          db
            .prepare(
              "SELECT * FROM admins WHERE username = ?"
            )
            .get(username);

        const passwordHash =
          hashPassword(password);

        if (
          !admin ||
          admin.password_hash !== passwordHash
        ) {

          return sendHtml(
            res,
            401,

            page(
              "Login Failed",

              `

              <div class="box">

                <div class="logo">
                  ⚔️ VergilPanel
                </div>

                <h1>
                  Login Failed
                </h1>

                <p class="error">
                  Username or password is incorrect.
                </p>

                <button
                  onclick="location.href='/login'"
                >
                  Try Again
                </button>

              </div>

              ${footer()}

              `
            )
          );

        }

        const token =
          createSession(admin);

        const secure =
          req.headers["x-forwarded-proto"] === "https"
            ? "; Secure"
            : "";

        return sendHtml(
          res,
          302,
          "",

          {
            Location: "/dashboard",

            "Set-Cookie":
              `vergil_session=${token}; HttpOnly; Path=/; SameSite=Lax${secure}`
          }
        );

      }


      // ==================================================
      // DASHBOARD
      // ==================================================

      if (
        req.method === "GET" &&
        path === "/dashboard"
      ) {

        const session =
          getSession(req);

        if (!session) {

          return sendHtml(
            res,
            302,
            "",

            {
              Location: "/login"
            }
          );

        }

        const adminCount =
          db
            .prepare(
              "SELECT COUNT(*) AS count FROM admins"
            )
            .get();

        return sendHtml(
          res,
          200,

          page(
            "Dashboard",

            `

            <div class="container">

              <div class="topbar">

                <div class="brand">
                  ⚔️ VergilPanel
                </div>

                <div class="admin">
                  Admin:
                  <strong>
                    ${escapeHtml(session.username)}
                  </strong>
                </div>

              </div>


              <div class="welcome">

                <h1>
                  Dashboard
                </h1>

                <p>
                  Welcome back,
                  ${escapeHtml(session.username)}
                  👋
                </p>

              </div>


              <div class="grid">


                <div class="card">

                  <div class="card-title">
                    Panel Status
                  </div>

                  <div class="card-value online">
                    🟢 Online
                  </div>

                </div>


                <div class="card">

                  <div class="card-title">
                    Database
                  </div>

                  <div class="card-value online">
                    🟢 Connected
                  </div>

                </div>


                <div class="card">

                  <div class="card-title">
                    Xray
                  </div>

                  <div class="card-value neutral">
                    ⚪ Not configured
                  </div>

                </div>


                <div class="card">

                  <div class="card-title">
                    Administrators
                  </div>

                  <div class="card-value">
                    ${adminCount.count}
                  </div>

                </div>


                <div class="card">

                  <div class="card-title">
                    Uptime
                  </div>

                  <div class="card-value">
                    ${formatUptime()}
                  </div>

                </div>


                <div class="card">

                  <div class="card-title">
                    Version
                  </div>

                  <div class="card-value">
                    v0.3.1
                  </div>

                </div>


              </div>


              <div class="actions">

                <div class="action">
                  👥
                  <br>
                  Users
                  <br>
                  <small>
                    Coming soon
                  </small>
                </div>


                <div class="action">
                  ⚡
                  <br>
                  Xray
                  <br>
                  <small>
                    Coming soon
                  </small>
                </div>


                <div class="action">
                  ⚙️
                  <br>
                  Settings
                  <br>
                  <small>
                    Coming soon
                  </small>
                </div>

              </div>


              <form
                method="POST"
                action="/logout"
                style="max-width:300px;margin:30px auto 0;"
              >

                <button
                  type="submit"
                  class="logout"
                >
                  Logout
                </button>

              </form>

            </div>


            ${footer()}

            `
          )
        );

      }


      // ==================================================
      // LOGOUT
      // ==================================================

      if (
        req.method === "POST" &&
        path === "/logout"
      ) {

        const token =
          getSessionToken(req);

        deleteSession(token);

        return sendHtml(
          res,
          302,
          "",

          {
            Location: "/login",

            "Set-Cookie":
              "vergil_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax"
          }
        );

      }


      // ==================================================
      // MAIN PAGE
      // ==================================================

      if (
        req.method === "GET" &&
        path === "/"
      ) {

        const session =
          getSession(req);

        if (session) {

          return sendHtml(
            res,
            302,
            "",

            {
              Location: "/dashboard"
            }
          );

        }

        const admin =
          db
            .prepare(
              "SELECT COUNT(*) AS count FROM admins"
            )
            .get();

        if (admin.count === 0) {

          return sendHtml(
            res,
            200,

            page(
              "Welcome",

              `

              <div class="box">

                <div class="logo">
                  ⚔️ VergilPanel
                </div>

                <h1>
                  Welcome
                </h1>

                <p>
                  Your panel is ready.
                </p>

                <button
                  onclick="location.href='/setup'"
                >
                  Start Setup
                </button>

              </div>

              ${footer()}

              `
            )
          );

        }

        return sendHtml(
          res,
          200,

          page(
            "VergilPanel",

            `

            <div class="box">

              <div class="logo">
                ⚔️ VergilPanel
              </div>

              <h1>
                VergilPanel
              </h1>

              <p>
                Xray management panel
              </p>

              <button
                onclick="location.href='/login'"
              >
                Login
              </button>

            </div>

            ${footer()}

            `
          )
        );

      }


      // ==================================================
      // 404
      // ==================================================

      return sendJson(
        res,
        404,
        {
          ok: false,
          error: "Not Found"
        }
      );


    } catch (error) {

      console.error(error);

      return sendJson(
        res,
        500,
        {
          ok: false,
          error: "Internal Server Error"
        }
      );

    }

  }
);


// ======================================================
// START SERVER
// ======================================================

server.listen(
  PORT,
  HOST,
  () => {

    console.log(
      `VergilPanel v0.3.1 running on ${HOST}:${PORT}`
    );

    console.log(
      `SQLite database: ${DB_PATH}`
    );

  }
);
