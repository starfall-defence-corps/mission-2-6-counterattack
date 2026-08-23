#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$ROOT_DIR/.docker"

echo ""
echo "=============================================="
echo "  STARFALL DEFENCE CORPS ACADEMY"
echo "  Resetting Fleet + Range (re-arming implants)..."
echo "=============================================="
echo ""

echo "  Destroying existing fleet + range..."
docker compose -f "$DOCKER_DIR/docker-compose.yml" down -v 2>&1 | while read -r line; do
    echo "    $line"
done

# Clear the range's latched state (C2 callbacks, uptime segment, baseline) so
# the next run starts from a fresh, freshly-armed fleet.
rm -f "$ROOT_DIR/.lab/uptime.json" "$ROOT_DIR/.lab/callbacks.json" \
      "$ROOT_DIR/.lab/baseline.json" 2>/dev/null || true

echo ""
echo "  Rebuilding fleet + range (recreating the compromised nodes)..."
# Reuse the setup script for the rebuild + re-arm.
bash "$SCRIPT_DIR/setup-lab.sh"
