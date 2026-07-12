#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
SYSD_DIR="${SYSD_DIR:-/etc/systemd/system}"
ETC_DIR="${ETC_DIR:-/etc/minecraft-ebpf}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/minecraft}"
GRAFANA_DIR="${GRAFANA_DIR:-$ETC_DIR/grafana}"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo

HERE=$(cd "$(dirname "$0")" && pwd)

for f in minecraft-ebpf minecraft-ebpf.service config.example \
         minecraft-ebpf-dashboard.json minecraft-ebpf-ips-dashboard.json; do
  [ -f "$HERE/$f" ] || {
    echo "missing $f next to install.sh — run install.sh from the unzipped release directory" >&2
    exit 1
  }
done

case "$(uname -s)" in
  Linux) ;;
  *) echo "minecraft-ebpf only runs on Linux (current: $(uname -s))" >&2; exit 1 ;;
esac

[ -e /sys/kernel/btf/vmlinux ] || {
  echo "kernel BTF missing at /sys/kernel/btf/vmlinux — need CONFIG_DEBUG_INFO_BTF=y" >&2
  exit 1
}

kmajor=$(uname -r | cut -d. -f1)
kminor=$(uname -r | cut -d. -f2)
if [ "$kmajor" -lt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -lt 17 ]; }; then
  echo "kernel $(uname -r) too old — need >= 5.17" >&2
  exit 1
fi

if ! [ -e /sys/fs/cgroup/cgroup.controllers ]; then
  echo "cgroup v2 not mounted at /sys/fs/cgroup" >&2
  exit 1
fi

WAS_RUNNING=0
if $SUDO systemctl is-active --quiet minecraft-ebpf 2>/dev/null; then
  WAS_RUNNING=1
  echo "stopping running minecraft-ebpf"
  $SUDO systemctl stop minecraft-ebpf
fi

if [ -d "$PIN_DIR" ]; then
  echo "clearing pinned BPF maps in $PIN_DIR (shapes can change between releases)"
  $SUDO rm -rf "$PIN_DIR"
fi

$SUDO install -m 0755 "$HERE/minecraft-ebpf" "$PREFIX/bin/minecraft-ebpf"
$SUDO install -m 0644 "$HERE/minecraft-ebpf.service" "$SYSD_DIR/minecraft-ebpf.service"
$SUDO mkdir -p "$ETC_DIR" "$GRAFANA_DIR"
$SUDO install -m 0644 "$HERE/minecraft-ebpf-dashboard.json"     "$GRAFANA_DIR/minecraft-ebpf-dashboard.json"
$SUDO install -m 0644 "$HERE/minecraft-ebpf-ips-dashboard.json" "$GRAFANA_DIR/minecraft-ebpf-ips-dashboard.json"

NEW_CONFIG=0
if [ ! -e "$ETC_DIR/config" ]; then
  $SUDO install -m 0644 "$HERE/config.example" "$ETC_DIR/config"
  NEW_CONFIG=1
else
  ADDED=""
  while IFS='=' read -r key val; do
    case "$key" in
      ''|\#*) continue ;;
    esac
    if ! $SUDO grep -q "^${key}=" "$ETC_DIR/config"; then
      printf "%s=%s\n" "$key" "$val" | $SUDO tee -a "$ETC_DIR/config" >/dev/null
      ADDED="$ADDED $key"
    fi
  done < "$HERE/config.example"
  if [ -n "$ADDED" ]; then
    echo "added new config keys to $ETC_DIR/config (defaults from this release):$ADDED"
  fi
fi

$SUDO systemctl daemon-reload

if [ "$WAS_RUNNING" = 1 ]; then
  echo "starting minecraft-ebpf"
  $SUDO systemctl start minecraft-ebpf
fi

echo
echo "installed $PREFIX/bin/minecraft-ebpf"
echo "  config:    $ETC_DIR/config"
echo "  unit:      $SYSD_DIR/minecraft-ebpf.service"
echo "  dashboards: $GRAFANA_DIR/ (import both .json files into Grafana)"
echo "              minecraft-ebpf-dashboard.json     — main metrics view"
echo "              minecraft-ebpf-ips-dashboard.json — per-IP listings (needs Infinity datasource)"
if [ "$NEW_CONFIG" = 1 ]; then
  echo
  echo "EDIT $ETC_DIR/config — IFACE is eth0 by default, probably wrong"
  echo "  $SUDO systemctl enable --now minecraft-ebpf"
fi
echo "  $SUDO systemctl status minecraft-ebpf"
echo "  sudo journalctl -u minecraft-ebpf -f"
