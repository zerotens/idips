# IDIPS – Intelligent DNS & Proxy Service

IDIPS is a service written in Go that works as a **DNS resolver, fake-IP allocator, SOCKS5/HTTP proxy, and admin UI**. Incoming client requests are forwarded to one of several upstreams (SOCKS5, HTTP CONNECT, or WireGuard via `wireproxy`) based on domain, IP, GeoIP, ASN, client, and port criteria.

The typical goal: reach Netflix, streaming services, or geo-restricted offerings through different egress IPs without configuring each client individually.

> **This project is vibecoded.** It was built with heavy AI assistance. Review the code and test it in your own environment before exposing it to untrusted networks.

## Features

- **Fake IP per destination domain** from a dedicated IPv4 pool (default `10.100.0.0/16`)
- **24h leases** (sliding, extended on DNS lookup and connection)
- **DNS server** UDP/TCP, optional DoH (`/dns-query`) and DoT
- **DNS forwarding** with an optional upstream through a SOCKS5/HTTP/WireGuard proxy
- **AAAA blocking** (enabled by default) to prevent IPv6 bypass
- **Routing engine**: domain (exact/suffix/regex), destination IP/CIDR, GeoIP, ASN, client CIDR, port, combined per rule with AND or OR
- **Upstream types**: SOCKS5, HTTP CONNECT, WireGuard via a `wireproxy` subprocess
- **Inbound**: SOCKS5, HTTP CONNECT, TPROXY (Linux)
- **Healthchecks**, failover via rule priority, test button in the UI
- **Admin UI** (Go templates + htmx, embedded) including auth, CSRF, and audit log
- **REST API** for automation
- **Live dashboard log** with client, target, destination ASN/country/organization, action, rule, and upstream for every connection
- **Bundled GeoIP data**: country and ASN lookups from the IPtoASN database, with MaxMind as fallback
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

### Kubernetes (Helm)

The Helm chart is published as an OCI artifact in the GitHub Container Registry:

```bash
helm install idips oci://ghcr.io/zerotens/idips/charts/idips \
  --version 0.3.0 \
  --namespace idips --create-namespace \
  --set auth.adminPassword='change-me'
```

See `deploy/helm/idips/values.yaml` for all available values. The chart uses the released container image from GHCR by default.

### Live dashboard

The dashboard streams the service log over Server-Sent Events at `/logs/stream` (admin session required). It shows the last 500 lines and reconnects automatically. Connection entries include the client IP, target host and port, destination IP, ASN, country, AS organization, fake IP, routing action, matched rule, and selected upstream. The same fields are written to the normal service log.

## Configuration

The most important options are managed in the admin UI under **Settings**:

| Area | Meaning |
|---|---|
| Fake IP pool | CIDR, lease TTL, DNS TTL, AAAA blocking, fake IP for all A queries |
| DNS | Listen address, upstream, UDP/TCP, DNS over proxy, DoH/DoT |
| Inbound | SOCKS5, HTTP CONNECT, TPROXY, optional auth |
| Default routing | `direct`, `proxy`, or `block` plus the default upstream |
| WireGuard | Path to the `wireproxy` binary and the data directory |
| GeoIP/ASN | Bundled IPtoASN database and/or MaxMind `.mmdb` paths |
| Admin | Listen address, TLS, API token |

**Listener and TLS changes require a restart.** Upstreams, rules, leases, and most routing options are read dynamically.

### GeoIP / ASN data

Container images and release archives include `ip2asn-combined.tsv.gz` from [iptoasn.com](https://iptoasn.com/), which provides both country and ASN for IPv4 and IPv6. IDIPS auto-detects it in these locations:

- `/usr/share/idips/ip2asn-combined.tsv.gz` in the container image
- next to the `idips` binary, in the data directory, or in the current working directory for release archives
- the path in `IDIPS_IPTOASN_DB`, if set

You can also set an explicit **IPtoASN database** path in Settings; the file may be plain TSV or `.tsv.gz`. IPtoASN is queried first and MaxMind `.mmdb` databases are used as a fallback when no range matches. IPtoASN country codes describe the country associated with the ASN range, not precise geolocation.

To refresh the database locally, run:

```bash
make geo
```

The release workflow downloads a fresh copy for every release, and the Docker build downloads it automatically. Rebuild or restart after replacing the file.

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

Rules are evaluated in ascending `priority` order. Each rule combines its non-empty criteria using its condition logic:

- **AND** (default): every configured criterion must match.
- **OR**: at least one configured criterion must match.

A rule with no criteria is a catch-all and matches everything. The port criterion is ignored during DNS/fake-IP decisions and enforced when a connection is established.

| Criterion | Example |
|---|---|
| Domain | `netflix.com`, `example.org` (comma-separated), regex `^ads\.` |
| Destination IP/CIDR | `203.0.113.0/24, 2001:db8::/32` |
| GeoIP | `DE, AT, CH` (IPtoASN or MaxMind) |
| ASN | `AS3320, AS15169` (IPtoASN or MaxMind) |
| Client CIDR | `192.168.1.0/24` |
| Port | `443`, `80,8000-8100` |

Actions:

- `proxy` → the selected upstream
- `direct` → direct connection
- `block` → connection is rejected

If the upstream of a matching `proxy` rule is disabled or `down`, evaluation continues with the next matching rule (failover by priority). After that, the default action applies.

## OpenWrt: redirect selected LAN clients through IDIPS

This setup steers only selected client IPs through IDIPS while all other devices keep using the router normally. It combines IDIPS DNS with SOCKS5 and `redsocks` on OpenWrt, so TPROXY is not required inside Kubernetes.

Flow:

1. The selected clients use IDIPS as their DNS server. IDIPS returns fake IPs from the configured pool for domains that match `proxy` or `block` rules.
2. The OpenWrt firewall redirects TCP connections to that fake-IP pool to a local `redsocks` instance.
3. `redsocks` forwards the original destination to IDIPS over SOCKS5.
4. IDIPS maps the fake IP back to the domain and applies its routing rules.

> **Important:** Choose a fake-IP pool that does not overlap your LAN, Kubernetes pod CIDR, or Kubernetes service CIDR. The default `10.100.0.0/16` overlaps the common kubeadm service CIDR `10.96.0.0/12`. This guide uses `198.18.0.0/16`; change the pool in IDIPS **Settings** and update the firewall rules below if you use another range.

### 1. Expose IDIPS on the LAN

The router must reach both DNS (UDP/TCP 53) and SOCKS5 (TCP 1080) on a stable IP. A `LoadBalancer` service is the simplest option (MetalLB, Cilium, or the k3s service load balancer):

```bash
helm upgrade --install idips oci://ghcr.io/zerotens/idips/charts/idips \
  --version 0.3.0 \
  --namespace idips --create-namespace \
  --set service.type=LoadBalancer \
  --set auth.adminPassword='change-me'

kubectl -n idips get service idips
```

Use the external IP from the output as `IDIPS_IP` below. With k3s this is usually the node IP; with MetalLB configure an address from your LAN range. DNS must be reachable on port `53`, so a `NodePort` service is not sufficient for DHCP-provided DNS. Protect the admin UI on `:8080` with a firewall and/or TLS.

In IDIPS **Settings**:

- Set the fake-IP pool to an unused range such as `198.18.0.0/16`.
- Optionally set the DNS upstream to your router's LAN IP (for example `192.168.1.1:53`) so local names keep resolving. Do not point the router's own DNS upstream back to IDIPS.
- Add upstreams and routing rules as usual, then create a test `proxy` rule.

Keep TPROXY disabled for this setup (`tproxy.enabled` is `false` by default in the chart).

### 2. Install and configure redsocks

```bash
opkg update && opkg install redsocks
# On newer OpenWrt releases that use apk:
# apk update && apk add redsocks
```

Edit `/etc/redsocks.conf` (the official OpenWrt package uses this file):

```conf
base {
    log_info = on;
    log = "syslog:local7";
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 0.0.0.0;
    local_port = 12345;
    ip = 192.168.1.200;
    port = 1080;
    type = socks5;
    // login = "idips";
    // password = "change-me";
}
```

Replace `192.168.1.200` with `IDIPS_IP`. If SOCKS5 authentication is enabled in IDIPS, uncomment and set the credentials. Some third-party LuCI packages use `/etc/config/redsocks` instead; in that case, put the same values in the UCI format.

Keep port `12345` blocked from the WAN side. Binding to `0.0.0.0` is required because nftables redirects forwarded traffic to the router's LAN address.

```bash
/etc/init.d/redsocks enable
/etc/init.d/redsocks restart
```

### 3. Give only the selected clients the IDIPS resolver

Assign a DHCP tag to the chosen hosts in `/etc/config/dhcp`:

```uci
config host
    option name 'idips-client'
    option mac 'AA:BB:CC:DD:EE:FF'
    option ip '192.168.1.50'
    list tag 'idips'

config dhcp 'lan'
    # keep your existing options
    list dhcp_option 'tag:idips,6,192.168.1.200'
```

Use the MAC/IP of each client and add one `config host` block per device; all clients with the tag receive the IDIPS DNS server. Reconnect the clients or renew their DHCP lease.

Some clients ignore DHCP DNS or use DoH/DoT and will bypass the fake-IP mapping. If needed, block DoT (TCP/UDP 853) for these clients and disable Private DNS or browser DoH.

### 4. Redirect the fake-IP pool to redsocks

Create `/etc/nftables.d/10-idips.nft` (OpenWrt 22.03+ with fw4):

```nft
chain idips_redirect {
    type nat hook prerouting priority dstnat; policy accept;
    ip saddr { 192.168.1.50, 192.168.1.51 } ip daddr 198.18.0.0/16 meta l4proto tcp counter redirect to :12345
}

chain idips_no_quic {
    type filter hook forward priority filter; policy accept;
    ip saddr { 192.168.1.50, 192.168.1.51 } ip daddr 198.18.0.0/16 udp dport 443 counter drop
}
```

Replace the client IPs and fake-IP pool with your values. Only TCP is redirected; IDIPS does not proxy UDP. Dropping QUIC to the fake pool forces browsers back to TCP. OpenWrt 21.02 and older use iptables by default; translate these rules to `iptables -t nat -A PREROUTING ... -j REDIRECT --to-ports 12345` plus a matching QUIC `DROP` rule.

Reload the firewall and inspect the chains:

```bash
fw4 reload
nft list chain inet fw4 idips_redirect
nft list chain inet fw4 idips_no_quic
```

### 5. Verify

From a selected client:

```bash
nslookup netflix.com
curl -v https://netflix.com
```

For a domain matched by a `proxy` rule, DNS should return an address from the fake-IP pool and traffic should appear in the IDIPS **Leases** page. On the router, the counters in `idips_redirect` should increase and `logread | grep -i redsocks` should show activity.

If the fake IP is returned but the connection fails, check that the router can reach `IDIPS_IP:1080` and that the SOCKS5 service is reachable. If DNS returns the real IP, the client is not using IDIPS DNS, or the domain matched a `direct` rule.

### Caveats

- `redsocks` terminates the client connection, so IDIPS sees the router as the SOCKS5 client. Rules or logging based on the original client IP will not work for proxied TCP traffic. DNS queries may still carry the client IP depending on the load balancer.
- Only TCP is proxied. UDP, including QUIC, is not; dropping QUIC to the fake pool avoids long timeouts but does not proxy it.
- IPv6 is not proxied and `AAAA` is blocked by IDIPS by default. Make sure selected clients cannot bypass the router over IPv6.
- DoH/DoT or hardcoded DNS resolvers bypass the fake-IP mapping. Enforce the DNS settings or block those protocols for the selected clients.
- The router and Kubernetes cluster must be able to route to each other; this assumes the IDIPS `LoadBalancer` IP is reachable from the LAN.

## TPROXY (transparent gateway)

TPROXY is only available on Linux and requires `CAP_NET_ADMIN`. On Kubernetes, prefer the OpenWrt/SOCKS5 approach above: TPROXY requires a `hostNetwork` pod plus node-level policy routing, and a normal Service with NAT rewrites the original destination. Example:

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

Other endpoints: `POST/PUT/DELETE /api/upstreams`, `POST/DELETE /api/rules`, `DELETE /api/leases/{id}`, `GET/PUT /api/settings`, `POST /api/upstreams/{id}/test`. Rule objects accept `match_logic` with `and` (default) or `or`.

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
internal/iptoasn       IPtoASN country/ASN database reader
internal/logstream     In-memory log fan-out for the live dashboard
internal/resolver      DNS upstream/cache
internal/dnsserver     DNS UDP/TCP, DoH, DoT
internal/proxy         SOCKS5, HTTP CONNECT, TPROXY
internal/upstream      SOCKS5/HTTP/WireGuard connectors
internal/web           Admin UI, auth, REST API
scripts                nftables TPROXY example
```
