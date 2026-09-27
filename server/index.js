import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import Database from "better-sqlite3";

const PORT = Number(process.env.PORT) || 8080;
const HOST = "0.0.0.0";

const DATA_DIR = process.env.DATA_DIR || "/app/data";
const DB_PATH = `${DATA_DIR}/vergilpanel.db`;

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

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function sendHtml(res, status, html) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8"
  });

  res.end(html);
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8"
  });

  res.end(JSON.stringify(data));
}

async function readBody(req) {
  let body = "";

  for await (const chunk of req) {
    body += chunk;
  }

  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

function page(title, content) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - VergilPanel</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      background: #0b1020;
      color: white;
      font-family: Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .box {
      width: 100%;
      max-width: 420px;
      background: #151c32;
      padding: 30px;
      border-radius: 18px;
      box-shadow: 0 20px 60px rgba(0,0,0,.4);
    }

    h1 {
      margin-top: 0;
      text-align: center;
    }

    p {
      color: #aab3cc;
      text-align: center;
    }

    input {
      width: 100%;
      padding: 14px;
      margin: 8px 0;
      border: 1px solid #303b5c;
      border-radius: 10px;
      background: #0e1426;
      color: white;
      font-size: 16px;
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

    .logo {
      text-align: center;
      font-size: 32px;
      font-weight: bold;
      margin-bottom: 10px;
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
  </style>
</head>

<body>

${content}

</body>
</html>
`;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(
      req.url || "/",
      `http://${req.headers.host || "localhost"}`
    );

    const path = url.pathname;

    // Health
    if (req.method === "GET" && path === "/health") {
      return sendJson(res, 200, {
        ok: true,
        service: "VergilPanel",
        version: "0.3.0",
        database: "sqlite"
      });
    }

    // API setup status
    if (req.method === "GET" && path === "/api/setup/status") {
      const admin = db
        .prepare("SELECT COUNT(*) AS count FROM admins")
        .get();

      return sendJson(res, 200, {
        setupRequired: admin.count === 0
      });
    }

    // Setup page
    if (req.method === "GET" && path === "/setup") {
      return sendHtml(
        res,
        200,
        page(
          "Setup",
          `
          <div class="box">
            <div class="logo">⚔️ VergilPanel</div>

            <h1>Initial Setup</h1>

            <p>Create your administrator account.</p>

            <form method="POST" action="/setup">
              <input
                type="text"
                name="username"
                placeholder="Username"
                required
              >

              <input
                type="password"
                name="password"
                placeholder="Password"
                required
              >

              <button type="submit">
                Create Admin
              </button>
            </form>
          </div>
          `
        )
      );
    }

    // Setup submit
    if (req.method === "POST" && path === "/setup") {
      const body = await readBody(req);

      if (
        !body ||
        typeof body.username !== "string" ||
        typeof body.password !== "string"
      ) {
        return sendJson(res, 400, {
          ok: false,
          error: "Username and password are required."
        });
      }

      const username = body.username.trim();
      const password = body.password;

      if (username.length < 3 || password.length < 6) {
        return sendJson(res, 400, {
          ok: false,
          error: "Username must be 3+ characters and password 6+ characters."
        });
      }

      const existing = db
        .prepare("SELECT COUNT(*) AS count FROM admins")
        .get();

      if (existing.count > 0) {
        return sendJson(res, 409, {
          ok: false,
          error: "Setup has already been completed."
        });
      }

      const passwordHash = hashPassword(password);

      db.prepare(`
        INSERT INTO admins
        (username, password_hash, created_at)
        VALUES (?, ?, ?)
      `).run(
        username,
        passwordHash,
        new Date().toISOString()
      );

      return sendHtml(
        res,
        200,
        page(
          "Setup Complete",
          `
          <div class="box">
            <div class="logo">⚔️ VergilPanel</div>

            <h1>Setup Complete</h1>

            <p class="success">
              Admin account created successfully.
            </p>

            <button onclick="location.href='/login'">
              Go to Login
            </button>
          </div>
          `
        )
      );
    }

    // Login page
    if (req.method === "GET" && path === "/login") {
      return sendHtml(
        res,
        200,
        page(
          "Login",
          `
          <div class="box">
            <div class="logo">⚔️ VergilPanel</div>

            <h1>Login</h1>

            <p>Sign in to your panel.</p>

            <form method="POST" action="/login">
              <input
                type="text"
                name="username"
                placeholder="Username"
                required
              >

              <input
                type="password"
                name="password"
                placeholder="Password"
                required
              >

              <button type="submit">
                Login
              </button>
            </form>
          </div>
          `
        )
      );
    }

    // Login submit
    if (req.method === "POST" && path === "/login") {
      const body = await readBody(req);

      if (!body) {
        return sendJson(res, 400, {
          ok: false,
          error: "Invalid request."
        });
      }

      const admin = db
        .prepare(
          "SELECT * FROM admins WHERE username = ?"
        )
        .get(String(body.username || "").trim());

      const passwordHash = hashPassword(
        String(body.password || "")
      );

      if (!admin || admin.password_hash !== passwordHash) {
        return sendHtml(
          res,
          401,
          page(
            "Login Failed",
            `
            <div class="box">
              <div class="logo">⚔️ VergilPanel</div>

              <h1>Login Failed</h1>

              <p class="error">
                Username or password is incorrect.
              </p>

              <button onclick="location.href='/login'">
                Try Again
              </button>
            </div>
            `
          )
        );
      }

      return sendHtml(
        res,
        200,
        page(
          "Dashboard",
          `
          <div class="box">
            <div class="logo">⚔️ VergilPanel</div>

            <h1>Dashboard</h1>

            <p class="success">
              Login successful.
            </p>

            <p>
              Welcome, ${admin.username} 👋
            </p>
          </div>
          `
        )
      );
    }

    // Main page
    if (req.method === "GET" && path === "/") {
      const admin = db
        .prepare("SELECT COUNT(*) AS count FROM admins")
        .get();

      if (admin.count === 0) {
        return sendHtml(
          res,
          200,
          page(
            "Welcome",
            `
            <div class="box">
              <div class="logo">⚔️ VergilPanel</div>

              <h1>Welcome</h1>

              <p>
                Your panel is ready.
              </p>

              <button onclick="location.href='/setup'">
                Start Setup
              </button>
            </div>
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
            <div class="logo">⚔️ VergilPanel</div>

            <h1>VergilPanel</h1>

            <p>
              Xray management panel
            </p>

            <button onclick="location.href='/login'">
              Login
            </button>
          </div>
          `
        )
      );
    }

    return sendJson(res, 404, {
      ok: false,
      error: "Not Found"
    });

  } catch (error) {
    console.error(error);

    return sendJson(res, 500, {
      ok: false,
      error: "Internal Server Error"
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`VergilPanel running on ${HOST}:${PORT}`);
  console.log(`SQLite database: ${DB_PATH}`);
});
