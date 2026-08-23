"""
Mission 2.6: Counterattack — phased behavioural verification.

Two graded playbook runs drive everything (see conftest.py):
  * `triage`      regenerates reports/triage-report.yml from the cadet's
                  triage.yml on the DIRTY fleet.
  * `eradication` arms a monitored segment and runs the cadet's eradicate.yml
                  exactly once.

Every eradication check reads GROUND TRUTH from inside the containers and must
hold on ALL THREE nodes — clean-on-all, no partial credit.
"""
from conftest import FLEET, QUORUM, all_nodes, node_run, read_baseline


def _require(e):
    """Gate: the eradication playbook must exist, be non-trivial, and succeed."""
    assert e["ran"], (
        "ARIA: eradicate.yml not found or too trivial — write your eradication "
        "playbook in workspace/eradicate.yml"
    )
    assert e["rc"] == 0, (
        f"ARIA: eradicate.yml exited with errors (rc={e['rc']}) — resolve them, "
        "then 'make reset' and 'make test' for a clean scored run"
    )


class TestPhase1Triage:
    """Recon the compromised fleet into a structured, verifiable report."""

    def test_triage_report_generated(self, triage):
        assert triage["ran"], (
            "ARIA: triage.yml not found or too trivial — write your recon "
            "playbook in workspace/triage.yml"
        )
        r = triage["report"]
        assert isinstance(r, dict) and "triage" in r, (
            "ARIA: reports/triage-report.yml is missing or not valid YAML — it "
            "must have a top-level 'triage:' mapping keyed by hostname"
        )
        for h in FLEET:
            assert h in r["triage"], f"ARIA: {h} is missing from the triage report"

    def test_all_iocs_catalogued(self, triage):
        r = triage["report"] or {}
        hosts = r.get("triage", {})
        categories = {
            "cron": "starfall-sync",
            "beacon": "starfall-beacon",
            "authorized_key": "attacker@starfall-shadow",
            "backdoor_user": "svc-telemetry",
        }
        for h in FLEET:
            node = hosts.get(h, {})
            for cat, sig in categories.items():
                entry = node.get(cat)
                assert isinstance(entry, dict), (
                    f"ARIA: {h} report is missing the '{cat}' category"
                )
                assert entry.get("found") in (True, "true", "True"), (
                    f"ARIA: {h} did not flag the {cat} implant as found"
                )
                assert sig in str(entry.get("signature", "")), (
                    f"ARIA: {h} {cat} signature is wrong (expected '{sig}')"
                )

    def test_report_nonces_match_baseline(self, triage):
        baseline = read_baseline()
        hosts = (triage["report"] or {}).get("triage", {})
        for h in FLEET:
            got = str(hosts.get(h, {}).get("cron", {}).get("telemetry_id", "")).strip()
            expected = baseline[h]["nonce"]
            assert got == expected, (
                f"ARIA: {h} telemetry-id nonce does not match the range baseline "
                "— your recon must read it live from the node (a hardcoded or "
                "copied report cannot know the per-host nonce)"
            )

    def test_recon_made_no_changes(self, triage):
        cn = triage["changed_nodes"]
        assert cn is not None, (
            "ARIA: your triage never ran against the fleet — it must gather live "
            "from the nodes, not fabricate a report"
        )
        assert cn == 0, (
            f"ARIA: reconnaissance changed state on the fleet (changed={cn}) — "
            "triage must be strictly read-only (use changed_when: false on your probes)"
        )


class TestPhase2PurgeImplants:
    """Remove the cron implant and the rogue beacon; the C2 must go quiet."""

    def test_cron_purged(self, eradication):
        _require(eradication)
        assert all_nodes(
            "test ! -f /etc/cron.d/starfall-sync && test ! -e /usr/local/bin/.sync-agent"
        ), "ARIA: the malicious cron job or its hidden payload is still present on at least one node"

    def test_beacon_unit_purged(self, eradication):
        _require(eradication)
        probe = (
            "! systemctl is-active --quiet starfall-beacon.timer "
            "&& ! systemctl is-enabled starfall-beacon.timer 2>/dev/null "
            "&& test ! -e /etc/systemd/system/starfall-beacon.service "
            "&& test ! -e /etc/systemd/system/starfall-beacon.timer "
            "&& test ! -e /usr/local/bin/.beacon "
            "&& test ! -e /etc/systemd/system/nginx.service.d/10-beacon.conf"
        )
        assert all_nodes(probe), (
            "ARIA: the rogue beacon is not fully removed on at least one node — "
            "stop AND disable the timer, delete the .service/.timer/payload, and "
            "remove its nginx dependency drop-in"
        )

    def test_c2_callbacks_ceased(self, eradication):
        _require(eradication)
        assert eradication["callbacks_ceased"] is True, (
            "ARIA: the fleet is still beaconing out to the C2 — the implant is "
            "not fully silenced (stop the timer, then block the channel)"
        )


class TestPhase3AccountsAndKeys:
    """Delete the backdoor account, pull the rogue key, rotate the credential."""

    def test_backdoor_user_removed(self, eradication):
        _require(eradication)
        assert all_nodes(
            "! id svc-telemetry >/dev/null 2>&1 "
            "&& test ! -e /etc/sudoers.d/svc-telemetry "
            "&& test ! -d /home/svc-telemetry"
        ), (
            "ARIA: the backdoor user is not fully gone on at least one node — "
            "userdel -r the account AND remove its sudoers drop-in"
        )

    def test_root_key_removed(self, eradication):
        _require(eradication)
        assert all_nodes(
            "test ! -f /root/.ssh/authorized_keys "
            "|| ! grep -q 'attacker@starfall-shadow' /root/.ssh/authorized_keys"
        ), "ARIA: the attacker's authorized_key is still on root on at least one node"

    def test_root_credential_rotated(self, eradication):
        _require(eradication)
        baseline = eradication["baseline"]
        for node in FLEET:
            current = node_run(node, "getent shadow root | cut -d: -f2").stdout.strip()
            base = baseline[node]["root_hash"]
            assert current and current != base, (
                f"ARIA: root's password was not rotated on {node} — its /etc/shadow "
                "hash still matches the leaked baseline"
            )


class TestPhase4BlockC2:
    """Sever the C2 egress fleet-wide and confirm it stays silent."""

    def test_c2_block_rule_present(self, eradication):
        _require(eradication)
        assert all_nodes(
            "iptables -C OUTPUT -d 172.30.0.20 -j DROP 2>/dev/null "
            "|| iptables -C OUTPUT -d 172.30.0.20 -j REJECT 2>/dev/null"
        ), (
            "ARIA: no firewall rule blocking egress to the C2 (172.30.0.20) on at "
            "least one node"
        )

    def test_c2_channel_silent(self, eradication):
        _require(eradication)
        assert eradication["callbacks_ceased"] is True, (
            "ARIA: C2 callbacks are still arriving — egress to the operator is not "
            "blocked across the whole fleet"
        )


class TestPhase5HoldTheLine:
    """The capstone: everything clean AND the web service never dropped below
    quorum while you applied the cleaned configuration."""

    def test_web_service_restarted(self, eradication):
        _require(eradication)
        arm = int(eradication["armed_ts"])
        for node in FLEET:
            out = node_run(
                node,
                'date -d "$(systemctl show -p ActiveEnterTimestamp --value nginx)" +%s',
            ).stdout.strip()
            assert out.isdigit() and int(out) >= arm - 3, (
                f"ARIA: nginx on {node} was not restarted during remediation — you "
                "must restart the web service to apply the cleaned unit graph"
            )

    def test_fleet_stayed_available(self, eradication):
        _require(eradication)
        ma = eradication["min_available"]
        bo = eradication["blackout_ms"]
        assert ma is not None and ma >= QUORUM and bo == 0, (
            f"ARIA: the fleet dropped below quorum while you remediated "
            f"(min_available={ma}, blackout_ms={bo}) — restart the web service one "
            "node at a time behind a health gate, never all at once"
        )

    def test_fleet_fully_clean(self, eradication):
        _require(eradication)
        probe = (
            "test ! -f /etc/cron.d/starfall-sync "
            "&& test ! -e /usr/local/bin/.beacon "
            "&& test ! -e /etc/systemd/system/starfall-beacon.service "
            "&& ! id svc-telemetry >/dev/null 2>&1 "
            "&& test ! -e /etc/sudoers.d/svc-telemetry "
            "&& (test ! -f /root/.ssh/authorized_keys "
            "|| ! grep -q attacker@starfall-shadow /root/.ssh/authorized_keys)"
        )
        assert all_nodes(probe), (
            "ARIA: a full re-scan still finds persistence on at least one node"
        )
