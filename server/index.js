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

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");

  if (!salt || !hash) {
    return false;
  }

  const candidate = crypto.scryptSync(password, salt, 64).toString("hex");

  if (candidate.length !== hash.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(candidate, "hex"),
    Buffer.from(hash, "hex")
  );
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

  if (!body) {
    return {};
  }

  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(
      req.url || "/",
      `http://${req.headers.host || "localhost"}`
    );

    const path = url.pathname;

    // Home
    if (req.method === "GET" && path === "/") {
      return sendJson(res, 200, {
        name: "VergilPanel",
        status: "running",
        version: "0.2.0"
      });
    }

    // Health check
    if (req.method === "GET" && path === "/health") {
      return sendJson(res, 200, {
        ok: true,
        service: "VergilPanel",
        version: "0.2.0",
        database: "sqlite"
      });
    }

    // Check initial setup
    if (req.method === "GET" && path === "/api/setup/status") {
      const row = db
        .prepare("SELECT COUNT(*) AS count FROM admins")
        .get();

      return sendJson(res, 200, {
        ok: true,
        setupRequired: row.count === 0
      });
    }

    // Create first admin
    if (req.method === "POST" && path === "/api/setup") {
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

      if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
        return sendJson(res, 400, {
          ok: false,
          error: "Invalid username."
        });
      }

      if (body.password.length < 8 || body.password.length > 128) {
        return sendJson(res, 400, {
          ok: false,
          error: "Password must be 8-128 characters."
        });
      }

      const existing = db
        .prepare("SELECT COUNT(*) AS count FROM admins")
        .get();

      if (existing.count > 0) {
        return sendJson(res, 409, {
          ok: false,
          error: "Initial setup has already been completed."
        });
      }

      const passwordHash = hashPassword(body.password);

      const result = db
        .prepare(
          `
          INSERT INTO admins
          (username, password_hash, created_at)
          VALUES (?, ?, ?)
          `
        )
        .run(
          username,
          passwordHash,
          new Date().toISOString()
        );

      return sendJson(res, 201, {
        ok: true,
        message: "Initial admin created.",
        adminId: result.lastInsertRowid
      });
    }

    // Login
    if (req.method === "POST" && path === "/api/login") {
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

      const admin = db
        .prepare(
          "SELECT * FROM admins WHERE username = ?"
        )
        .get(body.username.trim());

      if (
        !admin ||
        !verifyPassword(body.password, admin.password_hash)
      ) {
        return sendJson(res, 401, {
          ok: false,
          error: "Invalid credentials."
        });
      }

      return sendJson(res, 200, {
        ok: true,
        message: "Login credentials verified.",
        admin: {
          id: admin.id,
          username: admin.username
        }
      });
    }

    // 404
    return sendJson(res, 404, {
      ok: false,
      error: "Not Found",
      path
    });

  } catch (error) {
    console.error("Server error:", error);

    return sendJson(res, 500, {
      ok: false,
      error: "Internal Server Error"
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(
    `VergilPanel running on ${HOST}:${PORT}`
  );

  console.log(
    `SQLite database: ${DB_PATH}`
  );
});
