"""
ARIA Custom Test Reporter + Counterattack verification harness
==============================================================
Mission 2.6: Counterattack

The harness grades an incident-response *automation*, not a static end state, so
it runs the cadet's own playbooks:

  * triage.yml    — regenerated on the DIRTY fleet; the report is checked for
                    per-host structure, the four IOC signatures, and the
                    per-host telemetry-id nonce (which only a live triage can
                    surface — a hand-written report cannot fake it).

  * eradicate.yml — run ONCE inside a bracketed, armed window. The range's
                    uptime monitor latches the worst availability during that
                    window, so a naive parallel restart (fleet drops below
                    quorum) fails while a rolling serial:1 remediation passes.

Design principles:
  - Distinguish "the cadet removed it" from "it was never there" via the
    gitignored baseline recorded at `make setup` (.lab/baseline.json).
  - Assert eradication on ALL nodes with rc-encoded probes — any dirty node
    fails the whole check. No partial credit.
  - A dead/unarmed range reads as SKIP with a re-arm note, never a false pass.
"""
import json
import os
import subprocess
import time
import urllib.request

import pytest

# -- Range constants ---------------------------------------------------------

C2_IP = "172.30.0.20"                       # the C2 sink the cadet must block
TARGETS = ["172.30.0.11", "172.30.0.12", "172.30.0.13"]  # app / web / db
FLEET = ["sdc-app", "sdc-web", "sdc-db"]
RANGE_URL = "http://localhost:9000"
QUORUM = 2


# -- Paths -------------------------------------------------------------------

def _root_dir():
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(tests_dir, "..", "..", ".."))


def _workspace_dir():
    return os.path.join(_root_dir(), "workspace")


def _lab_dir():
    return os.path.join(_root_dir(), ".lab")


def _capped(timeout):
    """Optional ceiling on poll/settle timeouts. Unset in normal use; the
    range-build harness sets ARIA_MAX_WAIT to iterate quickly."""
    override = os.environ.get("ARIA_MAX_WAIT")
    if override:
        try:
            return min(timeout, int(override))
        except ValueError:
            pass
    return timeout


# -- Baseline (range attestation) --------------------------------------------

def read_baseline():
    try:
        with open(os.path.join(_lab_dir(), "baseline.json")) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        return None


# -- Range monitor HTTP API (never shell out to curl — the local dev proxy
#    rewrites curl output; urllib talks straight to the range) ---------------

def range_get(path, timeout=5):
    try:
        with urllib.request.urlopen(RANGE_URL + path, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


def range_arm(timeout=5):
    try:
        req = urllib.request.Request(RANGE_URL + "/arm", method="POST", data=b"")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


# -- Ansible + node probes ---------------------------------------------------

def run_ansible(args, timeout=240):
    """Run an ansible/ansible-playbook command in the cadet's workspace, using
    the workspace ansible.cfg + inventory + key (never the host's)."""
    env = dict(os.environ)
    env["ANSIBLE_CONFIG"] = os.path.join(_workspace_dir(), "ansible.cfg")
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout,
        cwd=_workspace_dir(), env=env,
    )


def node_run(node, cmd, timeout=20):
    """Run a shell command inside a fleet container and return the result. This
    reads GROUND TRUTH — we inspect the node directly rather than trusting the
    cadet's inventory — so eradication verification can't be gamed."""
    return subprocess.run(
        ["docker", "exec", node, "bash", "-lc", cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def all_nodes(probe):
    """True iff `probe` exits 0 on EVERY fleet node. A probe that exits non-zero
    on any still-dirty node fails the whole check — clean-on-all, no partial
    credit. Probes are pure reads."""
    return all(node_run(n, probe).returncode == 0 for n in FLEET)


def _lab_is_dirty():
    """The lab is 'armed/dirty' if the malicious cron implant is present on
    every node (a fresh `make setup`/`reset`). If it's gone everywhere, the
    fleet was already eradicated — grade from a fresh re-arm, don't false-pass."""
    return all_nodes("test -f /etc/cron.d/starfall-sync")


def _playbook_ok(name):
    """A deliverable exists and is non-trivial — i.e. at least one play actually
    does something (a non-empty tasks/roles/post_tasks list). An untouched
    skeleton (`tasks: []`) or a comment-only stub is trivial and fails."""
    path = os.path.join(_workspace_dir(), name)
    if not os.path.isfile(path):
        return False
    try:
        import yaml
        with open(path) as f:
            plays = yaml.safe_load(f)
    except Exception:
        return False
    if not isinstance(plays, list):
        return False
    for play in plays:
        if isinstance(play, dict) and any(
            play.get(k) for k in ("tasks", "roles", "post_tasks", "pre_tasks")
        ):
            return True
    return False


# ===========================================================================
#  Session fixtures — the two graded playbook runs
# ===========================================================================

@pytest.fixture(scope="session")
def triage():
    """Regenerate the triage report from the cadet's triage.yml on the DIRTY
    fleet, then parse it. Runs before eradication (recon is read-only)."""
    baseline = read_baseline()
    if baseline is None:
        pytest.skip("range baseline missing — run 'make setup' first")
    if not _lab_is_dirty():
        pytest.skip(
            "the fleet is already clean — run 'make reset' to re-arm the range, "
            "then 'make test' for a scored triage + eradication run"
        )

    result = {"report": None, "recap": "", "ran": False, "changed_nodes": None}
    if not _playbook_ok("triage.yml"):
        return result  # phase-1 tests will fail with a clear deficiency

    reports_dir = os.path.join(_workspace_dir(), "reports")
    subprocess.run(["rm", "-rf", reports_dir], capture_output=True)
    run = run_ansible(["ansible-playbook", "triage.yml"], timeout=180)
    result["ran"] = True
    result["recap"] = run.stdout or ""

    # changed=N on the fleet nodes (recon must mutate nothing)
    changed = []
    for line in result["recap"].splitlines():
        for host in FLEET:
            if line.strip().startswith(host) and "changed=" in line:
                try:
                    changed.append(int(line.split("changed=")[1].split()[0]))
                except (IndexError, ValueError):
                    pass
    result["changed_nodes"] = sum(changed) if changed else None

    report_path = os.path.join(reports_dir, "triage-report.yml")
    try:
        import yaml
        with open(report_path) as f:
            result["report"] = yaml.safe_load(f)
    except Exception:
        result["report"] = None
    return result


@pytest.fixture(scope="session")
def eradication():
    """Arm a monitored segment, run the cadet's eradicate.yml exactly once, and
    capture the resulting availability latch + callback cessation."""
    baseline = read_baseline()
    if baseline is None:
        pytest.skip("range baseline missing — run 'make setup' first")
    if not _lab_is_dirty():
        pytest.skip(
            "the fleet is already clean — run 'make reset' to re-arm the range, "
            "then 'make test' for a scored eradication run"
        )

    result = {
        "ran": False, "rc": None, "armed_ts": None,
        "min_available": None, "blackout_ms": None,
        "callbacks_ceased": None, "baseline": baseline,
    }
    if not _playbook_ok("eradicate.yml"):
        return result  # phase 2-5 tests will fail with a clear deficiency

    armed = range_arm()
    if not armed:
        pytest.skip("range monitor unreachable on :9000 — run 'make reset'")
    result["armed_ts"] = armed.get("armed_ts")

    run = run_ansible(["ansible-playbook", "eradicate.yml"], timeout=300)
    result["ran"] = True
    result["rc"] = run.returncode

    # Callback cessation: sample now, wait past one beacon interval, resample.
    after = range_get("/status")
    cb0 = after.get("callback_count_total") if after else None
    time.sleep(_capped(12))
    final = range_get("/status") or {}
    cb1 = final.get("callback_count_total")
    result["callbacks_ceased"] = (
        cb0 is not None and cb1 is not None and cb1 == cb0
    )
    result["min_available"] = final.get("min_available")
    result["blackout_ms"] = final.get("blackout_ms")
    return result


# ===========================================================================
# ARIA reporter — the phase-oriented summary is rendered by the shared
# `aria-reporter` pytest plugin (installed via requirements.txt). We only
# declare THIS mission's phases + friendly objective names; the plugin stays
# inert until configure() is called.
# ===========================================================================

from aria_reporter import configure  # noqa: E402

configure(
    mission_id="2-6",
    phases={
        "TestPhase1Triage":          ("1", "Triage the Fleet"),
        "TestPhase2PurgeImplants":   ("2", "Purge the Implants"),
        "TestPhase3AccountsAndKeys": ("3", "Accounts, Keys & Creds"),
        "TestPhase4BlockC2":         ("4", "Block the C2"),
        "TestPhase5HoldTheLine":     ("5", "Clean & Services Up"),
    },
    friendly={
        "test_triage_report_generated":      "Triage report generated from your playbook",
        "test_all_iocs_catalogued":          "All four implants catalogued on every node",
        "test_report_nonces_match_baseline": "Report carries each node's live telemetry-id",
        "test_recon_made_no_changes":        "Recon mutated nothing (changed=0)",
        "test_cron_purged":                  "Malicious cron + payload removed fleet-wide",
        "test_beacon_unit_purged":           "Rogue beacon unit stopped, disabled, deleted",
        "test_c2_callbacks_ceased":          "C2 callbacks have ceased",
        "test_backdoor_user_removed":        "Backdoor user + sudoers drop-in removed",
        "test_root_key_removed":             "Attacker's root authorized_key removed",
        "test_root_credential_rotated":      "Leaked root credential rotated",
        "test_c2_block_rule_present":        "C2 egress blocked across the fleet",
        "test_c2_channel_silent":            "C2 channel stayed silent after the block",
        "test_web_service_restarted":        "Web service restarted to apply clean config",
        "test_fleet_stayed_available":       "Fleet held quorum through the remediation",
        "test_fleet_fully_clean":            "Full re-scan: every node clean",
    },
)
