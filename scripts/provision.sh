#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo

$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  clang \
  llvm \
  build-essential \
  libbpf-dev \
  libelf-dev \
  libssl-dev \
  zlib1g-dev \
  git \
  curl \
  ca-certificates \
  pkg-config \
  socat \
  netcat-openbsd \
  tcpdump \
  golang-go

if ! command -v bpftool >/dev/null 2>&1; then
  tmp=$(mktemp -d)
  git clone --depth 1 --recurse-submodules \
    https://github.com/libbpf/bpftool "$tmp/bpftool"
  make -C "$tmp/bpftool/src" -j"$(nproc)"
  $SUDO make -C "$tmp/bpftool/src" install
  rm -rf "$tmp"
fi

$SUDO mkdir -p /sys/fs/bpf/minecraft
