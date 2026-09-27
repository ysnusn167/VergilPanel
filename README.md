# ⚔️ VergilPanel

A mobile-friendly, Railway-ready foundation for an open-source Xray management panel.

## Current version

`v0.1.0`

This first release intentionally contains only the application foundation:

- Node.js HTTP server
- Railway health check
- Docker deployment
- Environment-variable foundation
- `/health` endpoint
- `/` status endpoint

Xray management, authentication, database, subscriptions, QR codes and the web dashboard will be added in later versions.

## Run locally

Requires Node.js 22+.

```bash
npm start
```

Then open:

```text
http://localhost:8080/health
```

## Railway

Deploy this repository as a Railway service. Railway will build the included Dockerfile and use `/health` as the health check.

## Project direction

VergilPanel is being developed as an independent project. It is not a copy or rebranded distribution of another panel.

## License

License terms will be finalized before the first public production release.
