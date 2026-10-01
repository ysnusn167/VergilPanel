# VergilPanel 0.9.1 - changes

## Security
- Default login admin / admin is kept on fresh installs (first login redirects to Settings). The old bug is fixed: it is created only when no admin exists and is no longer reset to admin/admin on every restart. ADMIN_USERNAME / ADMIN_PASSWORD still work and can reset the password on boot.
- Passwords use scrypt with a per-password salt and constant-time comparison. Old SHA-256 hashes are upgraded automatically at the next login.
- Login brute-force protection: 8 failed attempts per IP per 5 minutes.
- Sessions expire after 7 days (cookie Max-Age too).
- Usernames limited to A-Z a-z 0-9 _ - (max 32).

## Connection strength
- No more lost updates: concurrent changes now queue one more Xray restart instead of being dropped.
- Expired users are removed from Xray automatically (checked every 30 seconds).
- Node's 5-minute request limit disabled so long XHTTP streams are not cut.
- WebSocket proxy: TCP keep-alive, no-delay, and both sides close together (no leaked sockets).
- HTTP proxy cleans up when the client or Xray drops.
- Xray outbound: IPv4 resolution + TCP keep-alive.
- Client links now include sni, fp=chrome and alpn.
- Subscription sends Profile-Update-Interval and the expiry date.

## Not done yet
- Real traffic limits (needs the Xray Stats API).
- Adding/removing users without restarting Xray.
- Dockerfile: pinned Xray version, npm ci, non-root user.

## 0.9.1
- Removed the untested Xray outbound tweaks (sockopt / domainStrategy / sniffing key) and the fp/alpn link parameters; the Xray config is back to the proven form.
- Startup now runs `xray run -test` and prints the result in the Railway log ("Xray config test").
- /health now shows `lastXrayExit` (why Xray last stopped).
