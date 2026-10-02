# VergilPanel 0.10.0

- New Settings card: Host + Port (used in generated TCP links), TCP protocol selector, internal port.
- New optional raw TCP inbound (one at a time, because Railway allows one TCP Proxy per service):
  - Shadowsocks 2022 (2022-blake3-aes-128-gcm), per-user keys derived from a server secret.
  - VLESS + Reality (xtls-rprx-vision), keys generated automatically with `xray x25519`.
- TCP link appears on the user's config page and inside the subscription.
- Changing protocol/port/Reality settings re-syncs Xray automatically.
- WS/XHTTP over 443 are unchanged.

# 0.10.1

- Channel logo added (server/assets/logo-96.jpg, logo-256.jpg): login page, top bar, favicon.
- Optional background: put `bg.jpg` (or `bg.webp` / `bg.png`) in `server/assets/` and it is applied automatically.

# 0.10.2

- Background image added (server/assets/bg.jpg, ~200KB) with a dark overlay for readable text; implemented as a fixed layer so it also works on iOS.
