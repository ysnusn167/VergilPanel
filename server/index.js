import http from "node:http";

const PORT = Number(process.env.PORT) || 8080;
const HOST = "0.0.0.0";

const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  if (req.url === "/health") {
    res.writeHead(200);
    res.end(
      JSON.stringify({
        ok: true,
        service: "VergilPanel",
        version: "0.1.0"
      })
    );
    return;
  }

  if (req.url === "/") {
    res.writeHead(200);
    res.end(
      JSON.stringify({
        name: "VergilPanel",
        status: "running",
        version: "0.1.0"
      })
    );
    return;
  }

  res.writeHead(404);
  res.end(
    JSON.stringify({
      ok: false,
      error: "Not Found"
    })
  );
});

server.listen(PORT, HOST, () => {
  console.log(`VergilPanel running on ${HOST}:${PORT}`);
});
