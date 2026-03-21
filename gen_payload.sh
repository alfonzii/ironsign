#!/usr/bin/env bash
set -euo pipefail

# Directory where this script lives (so "same directory" even if run from elsewhere)
DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Size: 4 KiB
SIZE=4096

# Get number of payloads from argument, default to 1
NUM_PAYLOADS="${1:-1}"

# Validate input
if ! [[ "$NUM_PAYLOADS" =~ ^[0-9]+$ ]] || [ "$NUM_PAYLOADS" -lt 1 ]; then
    echo "Error: argument must be a positive integer" >&2
    exit 1
fi

# Generate n payloads
for ((i=0; i<NUM_PAYLOADS; i++)); do
    NAME="payload_$i.bin"
    OUT="$DIR/$NAME"
    dd if=/dev/urandom of="$OUT" bs=1 count="$SIZE" status=none
    echo "Created: $OUT ($(stat -c%s "$OUT") bytes)"
done