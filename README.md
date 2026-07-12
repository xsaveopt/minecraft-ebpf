# minecraft-ebpf

Kernel-level L7 DDoS filter for a Minecraft (Java Edition) server. XDP parses the Minecraft handshake on ingress, splits Status pings from Login attempts and token-bucket-rate-limits each per source IP, runs the classic SYN/connection-flood circuit breakers, and blacklists IPs that flood protocol garbage. Prometheus metrics for every verdict.

## What it does

Minecraft Java listens on TCP port **25565**. Every connection opens with a Handshake packet — the first TCP data segment, never compressed or encrypted:

```
[VarInt length][VarInt packet id = 0x00][VarInt protocol version]
[String server address][u16 server port][VarInt next_state]
```

`next_state` is `1` for Status (the server-list ping), `2` for Login, `3` for Transfer. That one field is what the filter routes on.

**TCP path (XDP):**

- obviously-illegal TCP flag combinations (NULL, SYN+FIN, SYN+RST, FIN+RST, Xmas) → drop (`tcp_bad_flags`), checked before any map lookup and regardless of trust
- non-SYN from an IP with no SYN history and no established socket → drop (`no_syn`, the iptables `! --syn` flood filter)
- new SYN → per-IP open-connection cap, then per-IP new-connection (SYN) rate limit, then global new-connection rate limit (the circuit breaker)
- **Status handshake** (`next_state=1`, plus the legacy `0xFE` ping) → per-IP token bucket. The Status response carries the MOTD JSON (favicon, player sample, mod list) — the bandwidth-amplification vector. Bots connect, ping, read the multi-KB reply, repeat.
- **Login handshake** (`next_state=2`/`3`) → per-IP token bucket. Each Login Start drives the server through authentication, world entry, and entity spawn — far more expensive than a ping, and the bot-join flood vector. On a Login over an established socket, promote the source IP into `tcp_whitelist`.
- a segment that claims to be a handshake (packet id `0x00`) but decodes to a bogus `next_state` or an over-long address → drop as `malformed_handshake` and count an anomaly; enough anomalies in the window trip the blacklist
- established + whitelisted traffic still passes a per-IP packet/sec and byte/sec cap (`conn_ratelimit`). Trust skips handshake re-parsing and the global circuit breaker — **not** the rate cap or the open-connection cap. A source that completed a real login and then floods gets throttled, and enough overflow anomalies demote it out of the whitelist and onto the blacklist.

Everything else — Play packets on an existing connection, ACKs, fragments — passes untouched up to that per-IP rate cap. Only a positively-identified handshake is ever handshake-rate-limited, the same way the FiveM filter only acts on a matched `POST /client` / `GET /info.json`.

**State seeding (sockops):** a `sock_ops` program on the cgroup v2 root fires on `PASSIVE_ESTABLISHED_CB` for port 25565 and writes the client IP into `tcp_established`. Kernel TCP-state signal, not a payload guess — it's what makes whitelist promotion non-spoofable, since a forged source can't finish a real 3WHS. The same program tracks `tcp_open_count` via `STATE_CB`, and when an IP's last connection closes it clears that IP's `tcp_established` and `tcp_whitelist` entries — so trust is re-earned per session rather than lingering.

UDP is left untouched, so a Bedrock listener or anything else on the box is unaffected.

## Install

Download the release zip for your arch from the [releases page](https://github.com/xsaveopt/minecraft-ebpf/releases), unzip, and run the installer:

```sh
VERSION=v0.1.0
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -sfLO "https://github.com/xsaveopt/minecraft-ebpf/releases/download/$VERSION/minecraft-ebpf-$VERSION-linux-$ARCH.zip"
curl -sfLO "https://github.com/xsaveopt/minecraft-ebpf/releases/download/$VERSION/minecraft-ebpf-$VERSION-linux-$ARCH.zip.sha256"
sha256sum -c "minecraft-ebpf-$VERSION-linux-$ARCH.zip.sha256"
unzip -d minecraft-ebpf-$VERSION "minecraft-ebpf-$VERSION-linux-$ARCH.zip"
cd minecraft-ebpf-$VERSION && sudo sh install.sh
```

Then:

```sh
sudo vim /etc/minecraft-ebpf/config      # set IFACE and rate-limit values
sudo systemctl enable --now minecraft-ebpf
sudo systemctl status minecraft-ebpf
```

Zip contains binary, systemd unit, config example, install script, and two Grafana dashboards (main + per-IP listings) installed under `/etc/minecraft-ebpf/grafana/`. **Upgrades:** re-run `install.sh` from the new zip — it stops the daemon, wipes pinned maps (shapes change between releases), installs new files, appends any new config keys with their defaults, and restarts.

## Requirements

- Linux ≥ 6.1 (tested on Ubuntu 24.04 / kernel 6.8). `bpf_loop` needs 5.17+.
- `clang`, `llvm`, `libbpf-dev`, `libelf-dev`, `bpftool`, `linux-headers-$(uname -r)`
- Go 1.22+
- cgroup v2 (default on modern distros)

macOS users (Apple Silicon or Intel): use **OrbStack** for the Linux dev VM — arm64-native, handles BPF/XDP cleanly, mounts your home directory at the same path inside.

## Quick start (OrbStack on macOS)

One-time setup:

```sh
brew install --cask orbstack             # if you don't have it yet
orb create ubuntu:24.04 minecraft-ebpf   # creates the VM (~30s)
orb run -m minecraft-ebpf -w "$PWD" sudo bash scripts/provision.sh   # install toolchain
```

Day-to-day:

```sh
orb -m minecraft-ebpf                    # drops you into a shell inside the VM
# now inside the VM — your Mac home is mounted at /Users/<you>, not $HOME:
cd /Users/<you>/Documents/personal/dev/github/xsaveopt/minecraft-ebpf
make build
sudo ./bin/minecraft-ebpf run --iface eth0
```

From another terminal on your Mac: `curl http://$(orb info -m minecraft-ebpf -f '{{.IP}}'):9464/metrics` (or just `curl localhost:9464/metrics` — OrbStack auto-forwards).

## Quick start (bare metal / remote server)

```sh
make build
sudo ./bin/minecraft-ebpf run --iface <your-nic>
```

`make build` runs the bpf2go code generator and then `go build`. On first run you'll need `bpf/vmlinux.h` — `make` regenerates it from `/sys/kernel/btf/vmlinux` automatically.

## CLI

```
minecraft-ebpf run     [flags]                 attach BPF, serve /metrics + /api/*
minecraft-ebpf info                            counters + map sizes
minecraft-ebpf stats   [--json] [--watch 1s]   per-CPU stat counters
minecraft-ebpf top     --map M [-n 10]         hottest IPs in a per-IP map
minecraft-ebpf inspect <ipv4> [--watch 1s]     all per-IP state for one address, including cumulative drop counts by reason
minecraft-ebpf dump    --map M                 full listing of a map
minecraft-ebpf health  [--all]                 blacklisted IPs (--all: also tracked-but-not-banned)
minecraft-ebpf clear   --map M [--ip A]        wipe a map, or one IP from it
```

`M` is one of `whitelist`, `established`, `syn-seen`, `open-count`, `status-ratelimit`, `login-ratelimit`, `syn-ratelimit`, `conn-ratelimit`, `health`, `drop-history`, or `all`. Run `minecraft-ebpf run --help` for the daemon flags. All other subcommands operate directly on the pinned BPF maps; the daemon doesn't need to be reachable over HTTP.

## Metrics & API

`http://<addr>:9464` (configurable via `--metrics-addr`):

- `/metrics` — Prometheus counters. Main counter is `minecraft_xdp_packets_total{verdict,proto,reason}`; supporting counters/gauges are `minecraft_tcp_*_total`, `minecraft_map_entries{map}`, `minecraft_health_blacklisted_ips`, `minecraft_attached{program}`, `minecraft_build_info`. Labels are deliberately low-cardinality: there are no per-IP labels.
- `/api/info` — daemon overview (limits + map sizes + counter totals).
- `/api/stats` — counter values as JSON.
- `/api/top?map=<name>&n=<N>` — hottest IPs in one map (same ranking as `minecraft-ebpf top`).
- `/api/health[?all=1]` — blacklisted IPs; `?all=1` includes tracked-but-not-banned.
- `/api/whitelist` `/api/blacklist` `/api/established` `/api/syn-seen` `/api/open-count` — per-map listings.
- `/api/drop-history` — per-IP cumulative drop counts grouped by reason; pair with `/api/top?map=drop-history&reason=<name>` to rank.
- `/api/ip/<addr>` — every map's view of one IPv4 in a single JSON object, including a `drop_history` block. The "why was this player kicked" endpoint.
- `/api/state` — index.

The release ships two Grafana dashboards in `/etc/minecraft-ebpf/grafana/`: the main metrics dashboard, and a per-IP listings dashboard that needs the [Infinity datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) plugin (point it at your `:9464`).

## Capacity & throughput

Worked example: one server, 100 players, a public IPv4 on a **10 Gbps** uplink, native XDP on a real 10GbE NIC. There are two separate ceilings, and the lower one wins.

**1. Packet-rate ceiling (the CPU) — high.** A bare `XDP_DROP` runs [10–26 Mpps _per core_](https://blog.cloudflare.com/how-to-drop-10-million-packets/). This filter does more per packet — a whitelist lookup, syn_seen/established lookups, token buckets, and an LRU insert into `ip_drop_history` per unique source — so under a spoofed rand-source flood (≈2 LRU inserts/packet) it's closer to ~5–8 Mpps per core. But RSS spreads a spoofed flood across queues, so ~2–3 cores already reach **10GbE small-packet line rate, ≈14.88 Mpps** ([why 14.88](https://www.fmad.io/blog/what-is-10g-line-rate)), and an 8–16 core box has headroom to spare. The program is not what falls over at 10 Gbps.

**2. Bandwidth ceiling (the uplink) — 10 Gbps, and this is the real limit.** The attack's bytes arrive on your link _before_ XDP runs. XDP protects the CPU; it cannot un-congest a full pipe.

- **Small-packet flood** (SYN/ACK/small UDP, 64B frames): 10 Gbps = 14.88 Mpps. XDP drops it at the NIC; players are unaffected. This is the case it wins decisively — a raw Java server + kernel stack dies at a few hundred Kpps (softirq/conntrack/accept-queue), and `iptables` tops out ~2.5–4.5 Mpps; XDP lifts that survival ceiling to line rate, a 30–100× jump.
- **Large-packet / amplification flood** (1500B, reflection): 10 Gbps is only ~820 Kpps — trivial for XDP to drop — **but the pipe is now 100% full**, so legit packets are lost on the congested link upstream of XDP. Nothing host-side helps here.

100 vanilla players is a rounding error on 10G: client→server (what XDP filters) is ~4–6 Kpps / ~0.3 MB/s; server→client egress is ~40–120 Mbps. So effectively the whole link is free to absorb attack.

| Attack                                                                                               | In 10 Gbps? | Handled?                    |
| ---------------------------------------------------------------------------------------------------- | ----------- | --------------------------- |
| Booter/botter <1 Gbps — the [~99% case](https://blog.cloudflare.com/ddos-threat-report-for-2025-q1/) | ✅          | ✅ trivially                |
| SYN/ACK flood at line rate (~14.88 Mpps)                                                             | ✅          | ✅ dropped at the NIC       |
| ~10 Gbps amplification (large packets)                                                               | 🟡 fills it | ❌ uplink saturated         |
| Volumetric >10 Gbps ([record 31.4 Tbps](https://blog.cloudflare.com/ddos-threat-report-2025-q4/))    | ❌          | ❌ needs upstream scrubbing |

**Bottom line:** this comfortably beats the common case (sub-Gbps floods) and survives packet-rate floods up to 10G line rate — but its hard ceiling is 10 Gbps of _attack bandwidth_. Past that you need edge scrubbing (Cloudflare Spectrum, TCPShield, path.net, OVH VAC); on-box XDP and upstream scrubbing are complementary. Two things that wreck the CPU number: a cloud VPS stuck in **generic-mode** XDP (~1–2 Mpps — you want bare metal + a native-XDP NIC), and the distributed real-IP Login flood noted below.

## Known limitations

- **Java Edition only.** This is a TCP/25565 filter. Bedrock is a different protocol entirely (UDP/19132, RakNet) and is not handled — its packets pass through untouched.
- **No per-packet crypto auth.** A botnet of N real IPs can each push `N × --login-burst` valid Login handshakes before their buckets drain. The handshake parse stops protocol-garbage floods and the per-IP limits bound any single source, but a distributed flood of spec-compliant Logins from many real IPs is the hard case — same class of limitation as the FiveM filter's ENet check.
- **The L7 match is structural, not authenticated.** An attacker who completes a real 3WHS and sends a well-formed Login handshake passes the parse and (over an established socket) gets whitelisted — exactly as a real client would. This filter buys speed and connection-flood resistance, not a new auth primitive. Online-mode auth still happens in the server. Whitelisting is no longer a blank cheque, though: a trusted IP that then floods is still bounded by the per-IP `conn_ratelimit` (packets/sec + bytes/sec), the per-IP open-connection and new-connection caps, and gets demoted once its overflow anomalies trip the blacklist.
- **Behavioural L7 validation is out of scope.** XDP rate-caps established traffic but can't tell a valid Play packet from a well-formed junk one at line rate, nor reassemble streams. Protocol-aware filtering (keepalive cadence, movement sanity) belongs at a proxy (Velocity/BungeeCord) or a server plugin in front of this. And a volumetric flood that saturates the uplink itself is upstream of any host-side filter — that needs provider scrubbing.
- **Per-IP caps are shared across everything behind one IP.** Players sharing a NAT/CGNAT address share their `conn_ratelimit`, open-connection, and new-connection budgets. Defaults leave generous headroom (a moving player peaks well under 60 pps against a 300 pps cap), but very dense shared-IP setups may need `CONN_PPS`/`CONN_BURST` raised.
- **Online-mode bot defense is upstream of this.** Cracked/offline-mode servers are inherently more exposed to join floods; tighten `LOGIN_PER_MIN`/`LOGIN_BURST` accordingly.
- **IPv4 only.** Sockops uses `remote_ip4`. A server bound to `::` and reached over native v6 skips the filter — bind `0.0.0.0` explicitly, or put the v4 address in front.
- **XDP mode matters.** Native XDP for production numbers. Generic-mode fallback is correct but slow; the daemon logs which mode attached.

## Operational pitfalls

- **Upgrades and fresh installs reset the whitelist.** `install.sh` wipes `/sys/fs/bpf/minecraft/` so map shapes can change between releases. The sockops program only seeds `tcp_established` from `PASSIVE_ESTABLISHED_CB` on **new** TCP connections — already-connected players never re-trigger that callback. Since Minecraft players hold one long-lived connection, an established player whose connection survives the restart keeps flowing — their ongoing Play packets aren't handshakes, so they only meet the generous per-IP `conn_ratelimit` — but they won't be re-promoted to the whitelist until they reconnect. New joins during the window are bounded only by the per-IP login limit, which is the point. Plan disruptive upgrades for off-peak.
- **Plain `systemctl restart` is mostly safe** _only if you didn't change anything that alters pin shape_ (stat-slot count, map value types). Pins persist, the new daemon reuses the existing whitelist. If you bumped the binary across a release boundary outside of `install.sh`, hand-wipe `/sys/fs/bpf/minecraft/`.
- **`clear --map whitelist` (or `--map all`) drops every trusted IP.** Whitelisted players fall back to the rate-limited path until their next Login handshake re-promotes them. Don't run it on a live server unless that's what you want.
- **NAT or a TCP-terminating proxy in front collapses every player into one source IP.** Per-IP rate limits then starve legitimate traffic, and one bad client poisons the whole server. A BungeeCord/Velocity proxy, or HAProxy with PROXY protocol, is exactly this case — attach `minecraft-ebpf` on the **proxy's** ingress NIC (where real clients connect), not on the backend behind it. PROXY protocol / forwarded-IP headers are not parsed.
- **XDP is per-NIC.** With asymmetric routing or multi-homed setups, traffic that ingresses on a NIC the daemon isn't attached to is unfiltered. `--iface` must match the actual ingress path; multiple ingress NICs need multiple daemons.
- **Status rate limits can clip server-list scrapers.** Monitoring services and the client's multiplayer screen ping periodically. Default `STATUS_PER_MIN=60` is generous, but a busy public listing or an aggressive uptime monitor on one IP can hit it — watch `status_ratelimit` drops and raise it if they're legitimate.
- **Stale foreground `run` processes lie.** A `./bin/minecraft-ebpf run` left in a tmux pane keeps maps pinned and the `minecraft_attached=1` gauge true even after you `systemctl start minecraft-ebpf`, masking that the service unit failed to attach. Prefer `systemd-run --unit=minecraft-dbg` for debug runs, and check `pgrep -a minecraft-ebpf` before assuming the unit is the live daemon.

## Troubleshooting

- **`sockops: attach failed: permission denied`** — cgroup v2 not at `--cgroup` (default `/sys/fs/cgroup`). Check `mount | grep cgroup2`.
- **`attach xdp: native: …; generic: …`** — another XDP program is attached. `ip link set dev <iface> xdpgeneric off` and retry.
- **Legit players dropped as `login_ratelimit`.** A reconnect storm (server lag, a flaky client mod) can burn the bucket. Raise `LOGIN_PER_MIN`/`LOGIN_BURST`, or confirm you're not behind a proxy that NATs everyone to one IP.
- **Handshake never classifies.** Verify clients reach this NIC directly (`tcpdump -A -i <iface> 'tcp port 25565'` — you should see the handshake bytes). A proxy in front terminates the TCP connection and hides the client handshake; attach on the real frontend NIC.
- **Sockops doesn't fire for a containerized server.** Use the container's cgroup path (`cat /proc/<server-pid>/cgroup`), not the root.
