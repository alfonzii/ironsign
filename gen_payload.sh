#!/usr/bin/env bash
set -euo pipefail

# Directory where this script lives (so "same directory" even if run from elsewhere)
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Random filename
# NAME="payload_$(date +%Y%m%d_%H%M%S)_$RANDOM.bin"
NAME="payload.bin"
OUT="$DIR/$NAME"

# Size: 4 KiB
SIZE=4096

# Generate random bytes
# Linux: /dev/urandom is standard and fast
dd if=/dev/urandom of="$OUT" bs=1 count="$SIZE" status=none

echo "Created: $OUT ($(stat -c%s "$OUT") bytes)"
