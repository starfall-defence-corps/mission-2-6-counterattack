#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DOCKER_DIR="$ROOT_DIR/.docker"
SSH_DIR="$DOCKER_DIR/ssh-keys"
LAB_DIR="$ROOT_DIR/.lab"

NODES=(sdc-app sdc-web sdc-db)

echo ""
echo "=============================================="
echo "  STARFALL DEFENCE CORPS ACADEMY"
echo "  Mission 2.6: Counterattack"
echo "  Deploying compromised fleet + range..."
echo "=============================================="
echo ""

if ! python3 -m venv --help &>/dev/null; then
    echo "  ERROR: python3-venv is not installed."
    echo "  On Debian/Ubuntu: sudo apt install python3-venv"
    echo "  On Fedora/RHEL:   sudo dnf install python3-virtualenv"
    exit 1
fi

if [ ! -d "$ROOT_DIR/venv" ]; then
    echo "  Setting up Python environment..."
    python3 -m venv "$ROOT_DIR/venv"
    "$ROOT_DIR/venv/bin/pip" install -q -r "$ROOT_DIR/requirements.txt"
    echo "  Python environment ready."
    echo ""
fi

if [ ! -f "$SSH_DIR/cadet_key" ]; then
    echo "  Generating SSH credentials..."
    mkdir -p "$SSH_DIR"
    ssh-keygen -t ed25519 -f "$SSH_DIR/cadet_key" -N "" -C "cadet@starfall-academy" -q
    cp "$SSH_DIR/cadet_key.pub" "$SSH_DIR/authorized_keys"
    chmod 600 "$SSH_DIR/cadet_key"
    chmod 644 "$SSH_DIR/authorized_keys"
    echo "  SSH credentials generated."
    echo ""
fi

mkdir -p "$ROOT_DIR/workspace/.ssh"
cp "$SSH_DIR/cadet_key" "$ROOT_DIR/workspace/.ssh/cadet_key"
chmod 600 "$ROOT_DIR/workspace/.ssh/cadet_key"

# Host-side dir the range publishes into (C2 callbacks + uptime segment state).
# Bind-mounted read/write into sdc-noise at /lab. Gitignored.
mkdir -p "$LAB_DIR"
chmod 777 "$LAB_DIR" 2>/dev/null || true
rm -f "$LAB_DIR/uptime.json" "$LAB_DIR/callbacks.json" "$LAB_DIR/baseline.json" 2>/dev/null || true

echo "  Building fleet + range images..."
docker compose -f "$DOCKER_DIR/docker-compose.yml" up -d --build 2>&1 | while read -r line; do
    echo "    $line"
done

echo ""
echo "  Waiting for the fleet's SSH to become available..."
for node in sdc-app:2221 sdc-web:2222 sdc-db:2223; do
    name="${node%%:*}"
    port="${node##*:}"
    for i in $(seq 1 30); do
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 \
            -i "$SSH_DIR/cadet_key" cadet@localhost -p "$port" exit 2>/dev/null; then
            echo "    $name (port $port): ONLINE"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "    $name (port $port): TIMEOUT — check 'docker compose logs $name'"
        fi
        sleep 1
    done
done

echo ""
echo "  Waiting for the range monitor (sdc-noise) to come up..."
RANGE="OFFLINE"
for i in $(seq 1 30); do
    if curl -sf -m 2 http://localhost:9000/healthz >/dev/null 2>&1; then
        RANGE="ONLINE"
        break
    fi
    sleep 1
done
echo "    Range monitor: ${RANGE}"
if [ "$RANGE" != "ONLINE" ]; then
    echo "    ERROR: the range monitor never answered. Check 'docker compose logs sdc-noise'."
    exit 1
fi

# =============================================================================
#  RANGE ATTESTATION (the linchpin) — inject per-host nonce, verify all four
#  implants are present, and record each node's root shadow hash to the
#  baseline. This is what lets the harness tell "the cadet removed it" from
#  "it was never there", and grade credential rotation without knowing the
#  new secret.
# =============================================================================
echo ""
echo "  Arming the range (planting per-host nonce + baseline attestation)..."

ATTEST_TSV="$(mktemp)"
armed_ok=1
for node in "${NODES[@]}"; do
    nonce="$(openssl rand -hex 6 2>/dev/null || head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    # Inject the per-host telemetry-id nonce into the malicious cron comment.
    docker exec "$node" sed -i "s/__NONCE__/${nonce}/" /etc/cron.d/starfall-sync

    # Verify all four implants are present (hard fail — "range not armed").
    missing=""
    docker exec "$node" test -f /etc/cron.d/starfall-sync || missing+=" cron"
    docker exec "$node" bash -c "grep -q \"telemetry-id: ${nonce}\" /etc/cron.d/starfall-sync" || missing+=" nonce"
    docker exec "$node" systemctl is-enabled starfall-beacon.timer >/dev/null 2>&1 || missing+=" beacon-timer"
    docker exec "$node" test -f /usr/local/bin/.beacon || missing+=" beacon-payload"
    docker exec "$node" bash -c "grep -q 'attacker@starfall-shadow' /root/.ssh/authorized_keys" || missing+=" root-key"
    docker exec "$node" id svc-telemetry >/dev/null 2>&1 || missing+=" backdoor-user"
    docker exec "$node" test -f /etc/sudoers.d/svc-telemetry || missing+=" sudoers"
    if [ -n "$missing" ]; then
        echo "    $node: RANGE NOT ARMED — missing implants:$missing"
        armed_ok=0
    else
        echo "    $node: 4 implants planted, nonce injected"
    fi

    roothash="$(docker exec "$node" bash -c "getent shadow root | cut -d: -f2")"
    printf '%s\t%s\t%s\n' "$node" "$nonce" "$roothash" >> "$ATTEST_TSV"
done

if [ "$armed_ok" -ne 1 ]; then
    rm -f "$ATTEST_TSV"
    echo ""
    echo "  ERROR: the range failed to arm. The compromised image did not plant"
    echo "  every implant. Run 'make reset' to rebuild from a clean image."
    exit 1
fi

# Write the gitignored baseline the harness reads (nonce + root shadow hash
# per node), assembled robustly from the attestation TSV.
python3 - "$ATTEST_TSV" "$LAB_DIR/baseline.json" <<'PYEOF'
import json, sys
baseline = {}
with open(sys.argv[1]) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        node, nonce, root_hash = line.split("\t", 2)
        baseline[node] = {"nonce": nonce, "root_hash": root_hash}
with open(sys.argv[2], "w") as f:
    json.dump(baseline, f, indent=2)
PYEOF
rm -f "$ATTEST_TSV"
echo "    Baseline recorded: .lab/baseline.json"

echo ""
echo "=============================================="
echo "  Fleet Status: 3 nodes ONLINE — and COMPROMISED."
echo ""
echo "  Intrusion detected across the fleet. Persistence"
echo "  implants are dug in on every node and beaconing out"
echo "  to an unknown operator. Triage, then eradicate — and"
echo "  keep the web service up while you do it."
echo ""
echo "  Your workspace: workspace/"
echo "  Start here:     docs/BRIEFING.md"
echo "  Verify work:    make test"
echo "=============================================="
echo ""
