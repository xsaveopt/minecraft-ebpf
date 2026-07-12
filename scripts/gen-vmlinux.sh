#!/usr/bin/env bash
set -euo pipefail

OUT="$(dirname "$0")/../bpf/vmlinux.h"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$OUT"
echo "wrote $OUT"
