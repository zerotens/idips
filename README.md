# IDIPS – Intelligent DNS & Proxy Service

IDIPS is a service written in Go that works as a **DNS resolver, fake-IP allocator, SOCKS5/HTTP proxy, and admin UI**. Incoming client requests are forwarded to one of several upstreams (SOCKS5, HTTP CONNECT, or WireGuard via `wireproxy`) based on domain, IP, GeoIP, ASN, client, and port criteria.

The typical goal: reach Netflix, streaming services, or geo-restricted offerings through different egress IPs without configuring each client individually.

## Features

- **Fake IP per destination domain** from a dedicated IPv4 pool (default `10.100.0.0/16`)
- **24h leases** (sliding, extended on DNS lookup and connection)
- **DNS server** UDP/TCP, optional DoH (`/dns-query`) and DoT
- **DNS forwarding** with an optional upstream through a SOCKS5/HTTP/WireGuard proxy
- **AAAA blocking** (enabled by default) to prevent IPv6 bypass
- **Routing engine**: domain (exact/suffix/regex), destination IP/CIDR, GeoIP, ASN, client CIDR, port
- **Upstream types**: SOCKS5, HTTP CONNECT, WireGuard via a `wireproxy` subprocess
- **Inbound**: SOCKS5, HTTP CONNECT, TPROXY (Linux)
- **Healthchecks**, failover via rule priority, test button in the UI
- **Admin UI** (Go templates + htmx, embedded) including auth, CSRF, and audit log
- **REST API** for automation
- **SQLite** (WAL), encrypted secrets (AES-GCM), a single binary

## Quick start

### Local

```bash
go build -o idips ./cmd/idips
./idips -data ./data
```

On first start, an admin is created:

- Default: `admin` / `admin`
- Or set `IDIPS_ADMIN_USER` and `IDIPS_ADMIN_PASSWORD`

The admin UI runs on <http://127.0.0.1:8080> by default.

DNS on port 53 requires root privileges or `CAP_NET_BIND_SERVICE`. Alternatively, set a high port in Settings (for example `:5353`) and restart the service. Otherwise, the DNS error at startup is only a log entry; the admin UI and proxies continue to run.

> **Important:** The default admin is only intended for the first start. Set `IDIPS_ADMIN_PASSWORD` before the first start, or change the password afterwards in the admin UI under **Account**.

### systemd

A unit example is provided in `deploy/idips.service`. It uses `CAP_NET_BIND_SERVICE` for port 53 and `CAP_NET_ADMIN` for TPROXY:

```bash
sudo useradd --system --home /var/lib/idips --shell /usr/sbin/nologin idips
sudo install -m 0644 deploy/idips.service /etc/systemd/system/idips.service
sudo systemctl daemon-reload
sudo systemctl enable --now idips
```

### Docker

```bash
docker compose up -d --build
```

The Compose file maps admin (`8080`), SOCKS5 (`1080`), HTTP (`8081`), and DNS (`5353` on host to container port `53`). For TPROXY, see below; it requires `network_mode: host` and `NET_ADMIN`.

## Configuration

The most important options are managed in the admin UI under **Settings**:

| Area | Meaning |
|---|---|
| Fake IP pool | CIDR, lease TTL, DNS TTL, AAAA blocking, fake IP for all A queries |
| DNS | Listen address, upstream, UDP/TCP, DNS over proxy, DoH/DoT |
| Inbound | SOCKS5, HTTP CONNECT, TPROXY, optional auth |
| Default routing | `direct`, `proxy`, or `block` plus the default upstream |
| WireGuard | Path to the `wireproxy` binary and the data directory |
| GeoIP/ASN | Paths to MaxMind `.mmdb` files |
| Admin | Listen address, TLS, API token |

**Listener and TLS changes require a restart.** Upstreams, rules, leases, and most routing options are read dynamically.

### Upstreams

- **SOCKS5**: `host:port`, optionally with username/password. The destination domain is passed to the SOCKS5 server (remote DNS).
- **HTTP CONNECT**: `host:port`, optionally with basic auth.
- **WireGuard**: Standard WireGuard/wg-quick INI configuration (`[Interface]` + `[Peer]`), from which IDIPS generates a wireproxy config and starts `wireproxy` as a supervised subprocess. Example:

```ini
[Interface]
PrivateKey = BASE64_PRIVATE_KEY=
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = BASE64_PEER_PUBLIC_KEY=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Multiple `[Peer]` sections are supported. `[Socks5]`/`[http]` sections from a wireproxy config are ignored because IDIPS manages these itself.

The `wireproxy` binary must be installed:

```bash
go install github.com/pufferffish/wireproxy/cmd/wireproxy@v1.0.10
```

## Fake-IP and routing flow

1. The client asks the IDIPS DNS server for `netflix.com`.
2. IDIPS resolves the real IP through the configured DNS upstream (optionally through a proxy).
3. The routing engine decides: `proxy`, `direct`, or `block`.
4. For `proxy`/`block` (or `fake_all`), a fake IP is allocated from the pool for 24h and returned as the A record.
5. The client connects to the fake IP via SOCKS5/HTTP or TPROXY.
6. IDIPS looks up the lease, determines the destination domain, evaluates the rules again, and connects through the selected upstream. For SOCKS5, the domain is preferably passed to the upstream (no DNS leak).

For `direct` rules, the real DNS answer is returned unless `fake_all` is enabled.

### Important DNS notes

- Clients must use the IDIPS DNS server. Anyone using DoH/DoT at a different resolver bypasses the fake-IP mapping.
- `AAAA` is answered empty by default. This prevents IPv6 bypass.
- For SOCKS5/HTTP clients, the fake IP does not need to be routable because the client passes it to the proxy as the destination.
- With TPROXY, the fake IP route must point to the IDIPS host (see the nftables script).

## Routing rules

Rules are evaluated in ascending `priority` order. All configured criteria must match (AND). An empty criteria set is a catch-all rule.

| Criterion | Example |
|---|---|
| Domain | `netflix.com`, `example.org` (comma-separated), regex `^ads\.` |
| Destination IP/CIDR | `203.0.113.0/24, 2001:db8::/32` |
| GeoIP | `DE, AT, CH` (MaxMind City) |
| ASN | `AS3320, AS15169` (MaxMind ASN) |
| Client CIDR | `192.168.1.0/24` |
| Port | `443`, `80,8000-8100` |

Actions:

- `proxy` → the selected upstream
- `direct` → direct connection
- `block` → connection is rejected

If the upstream of a matching `proxy` rule is disabled or `down`, evaluation continues with the next matching rule (failover by priority). After that, the default action applies.

## TPROXY (transparent gateway)

TPROXY is only available on Linux and requires `CAP_NET_ADMIN`. Example:

```bash
sudo ./scripts/nftables-tproxy.sh
```

By default, the script configures:

- Fake IP pool `10.100.0.0/16`
- TPROXY port `1082`
- Policy routing table `100`

Adjust the variables in the script if you use a different pool or port. For a gateway, also enable IP forwarding:

```bash
sysctl -w net.ipv4.ip_forward=1
```

Clients using TPROXY must point their DNS at IDIPS. Optionally, the script can redirect DNS port 53 traffic to IDIPS (commented-out rules).

## DoH / DoT

- **DoH** is always available at `/dns-query` on the admin listener (GET `?dns=` or POST `application/dns-message`). A separate `doh_listen` can optionally be configured.
- **DoT** is enabled via `dot_listen`, `dns_cert`, and `dns_key`.

## REST API

Authentication:

- `Authorization: Bearer <api_token>` (set in Settings), or
- Session cookie from the admin UI plus `X-CSRF-Token`.

Examples:

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/upstreams
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/rules
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/leases?q=netflix
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/health
```

Other endpoints: `POST/PUT/DELETE /api/upstreams`, `POST/DELETE /api/rules`, `DELETE /api/leases/{id}`, `GET/PUT /api/settings`, `POST /api/upstreams/{id}/test`.

## Data and secrets

- SQLite: `<data>/idips.db`
- Master key: `<data>/master.key` (or `IDIPS_MASTER_KEY`)
- Wireproxy configs: `<data>/wireproxy/wg-<id>.conf` (0600)
- Upstream passwords and WireGuard keys are stored encrypted with AES-GCM.
- Backups: back up the SQLite file plus `master.key`; without the key, the secrets cannot be decrypted.

## Security

- The admin UI uses no TLS by default. For production, configure TLS via `admin_tls_cert`/`admin_tls_key` or use a reverse proxy.
- Change the admin password after the first start under **Account**.
- DNS is an open resolver if it is publicly reachable. Put a firewall/ACL in front of it.
- Use an API token of at least 16 characters; preferably generate it randomly.
- Apply TPROXY rules only on the intended gateway.
- `wireproxy` subprocesses run with the privileges of the IDIPS process.

## Tests

```bash
go test ./...
go vet ./...
```

## Limitations (MVP)

- **TCP** proxying only; no SOCKS5 UDP ASSOCIATE.
- The fake-IP pool is **IPv4**; AAAA is blocked by default.
- The HTTP inbound supports **CONNECT only**, not absolute HTTP requests.
- WireGuard profiles are started as a wireproxy subprocess; no in-process WireGuard.
- Listener and TLS changes require a restart; the log level is applied dynamically.
- No HA/multi-node support; SQLite is single-node.

## Project structure

```
cmd/idips              Entry point
internal/app           Wiring, lifecycle
internal/store         SQLite, migrations, settings
internal/alloc         Fake-IP allocator and leases
internal/routing       Rule engine incl. GeoIP/ASN
internal/resolver      DNS upstream/cache
internal/dnsserver     DNS UDP/TCP, DoH, DoT
internal/proxy         SOCKS5, HTTP CONNECT, TPROXY
internal/upstream      SOCKS5/HTTP/WireGuard connectors
internal/web           Admin UI, auth, REST API
scripts                nftables TPROXY example
```
