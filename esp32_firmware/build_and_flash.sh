#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "Build remote firmware (creates firmware.bin)"
cd "$ROOT/remote"
platformio run

echo "Copy firmware to sensing data and build filesystem"
BIN=$(ls .pio/build/*/firmware.bin 2>/dev/null | head -n1)
if [ -z "$BIN" ]; then
  echo "Could not find firmware.bin in .pio/build/. Build failed?" >&2
  exit 1
fi
mkdir -p ../sensing/data
cp "$BIN" ../sensing/data/firmware.bin

echo "Build FS image for sensing and upload sensing firmware"
cd ../sensing
platformio run --target buildfs || true
platformio run --target upload

echo "Done. Flashing complete."
