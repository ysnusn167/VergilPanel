# VergilPanel

Open-source foundation for a Railway-ready Xray management panel.

## v0.2.0

- Node.js HTTP API
- SQLite database
- Persistent data directory at `/app/data`
- First-admin setup endpoint
- Password hashing with Node.js `scrypt`
- Login credential verification endpoint
- Railway/Docker compatible

## API

- `GET /`
- `GET /health`
- `GET /api/setup/status`
- `POST /api/setup`
- `POST /api/login`

## Railway

Attach a persistent Railway Volume to `/app/data`.

## Development

```bash
npm install
npm start
```
