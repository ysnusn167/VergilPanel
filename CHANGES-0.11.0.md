# VergilPanel 0.11.0

- Multi-protocol subscriptions: creating a sub now needs only a name. The panel automatically puts every enabled protocol in the subscription.
- New protocols (all work on the HTTPS domain, port 443, no TCP Proxy needed):
  - VLESS + HTTPUpgrade
  - VMess + WebSocket, VMess + HTTPUpgrade
  - Trojan + WebSocket, Trojan + HTTPUpgrade
  - Shadowsocks 2022 + WebSocket
- Existing VLESS + XHTTP and VLESS + WebSocket are unchanged.
- New Settings card "Protocols": turn individual protocols on/off (applies to all users, Xray re-syncs automatically).
- Protocols are defined in one table (`PROTOCOLS` in server/index.js); inbounds, proxy routing, links and subscription are generated from it.
- Trojan passwords and Shadowsocks user keys are derived from each user's UUID, so no database change is needed.
- User config page: one collapsible card (link, copy, QR) per protocol.
- New-sub form: traffic limit and expiry moved under "optional settings".
- Internal ports: 10001-10008 (127.0.0.1 only). Paths: /xhttp, /ws, /vl-hu, /vmess, /vmess-hu, /trojan, /trojan-hu, /ss.
