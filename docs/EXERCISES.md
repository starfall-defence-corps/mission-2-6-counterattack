---
CLASSIFICATION: LIEUTENANT EYES ONLY
MISSION: 2.6 — COUNTERATTACK
DOCUMENT: EXERCISES — Phase-by-Phase Operational Instructions
---

# EXERCISES — MISSION 2.6: COUNTERATTACK

Complete each phase in sequence. Run `make test` after each phase. Do not
advance until ARIA confirms compliance.

**Two directories, two purposes:**

- **Ansible commands** (`ansible`, `ansible-playbook`): Run from `workspace/` where `ansible.cfg` lives.
- **Make commands** (`make test`, `make reset`): Run from the **project root** (where the `Makefile` lives).

When a phase says "Run ARIA's Verification", return to the project root first:

```bash
cd ..        # from workspace/ back to project root
make test
cd workspace # return to workspace for the next phase
```

**A note on `make test`**: it exercises **both of your deliverables against
the live fleet** every time — it regenerates `reports/triage-report.yml` by
re-running your `triage.yml`, then arms a monitored segment and runs your
`eradicate.yml` **exactly once**, latching the worst availability it observes
during that run. Because eradication is graded on live availability, running
it more than once against an already-clean fleet won't score you anything —
if you want a clean, freshly scored pass, run `make reset` first.

If ARIA ever reports every check as **skipped**, this is never counted as a
pass or a fail — it means the fleet is already clean (from a prior
`eradicate.yml` run) and there is nothing left to triage or eradicate. Run
`make reset` and try again.

There are exactly **two files** you write in this mission:
`workspace/triage.yml` (Phase 1) and `workspace/eradicate.yml` (Phases 2-5).
Both filenames are fixed — ARIA runs them by name.

---

## PHASE 0: Launch the Fleet, Confirm the Compromise

> Before you can respond to an incident, you need a fleet under one. Launch
> it, then confirm the implants are actually present.

### Step 0.1 — Preflight Check

From the **project root directory**, confirm your machine is mission-ready:

```bash
make doctor
```

### Step 0.2 — Start the Fleet and the Range

From the **project root directory** (not `workspace/`), run:

```bash
make setup
```

This builds the Docker containers, generates SSH credentials, starts all
three fleet nodes already carrying the four implants, and brings up the
range's C2 sink and uptime monitor.

### Step 0.3 — Activate the Python Environment

`make setup` creates a Python virtual environment with Ansible and testing
tools. **Activate it** before running any Ansible commands:

```bash
source venv/bin/activate
```

Your terminal prompt will show `(venv)` when active. You need to do this once
per terminal session. If you open a new terminal, activate again.

### Step 0.4 — Orient Yourself

You are not attacking anything in this mission — you are the incident
responder. The Operator's infrastructure (`sdc-noise`, 172.30.0.20) is opaque
range infrastructure: you will never see its code or touch its container.
Everything you write lives in `workspace/`, targets your own fleet, and is
applied fleet-wide.

Take a look at what's already scaffolded for you:

```bash
cd workspace
cat triage.yml
cat eradicate.yml
cat inventory/hosts.yml
```

Both playbooks are stubs (`tasks: []`) with header comments describing
exactly what "done" looks like for each. You will fill them in as you work
through the phases below. Skim the header comments now — they are your
spec.

### Step 0.5 — Confirm the Compromise Yourself

Before writing anything, SSH into a node and look at the implants directly —
you should be able to point at each one before you automate finding it:

```bash
make ssh-app
cat /etc/cron.d/starfall-sync
systemctl status starfall-beacon.timer
tail -3 /root/.ssh/authorized_keys
id svc-telemetry
exit
```

### Step 0.6 — If Things Go Wrong

If containers are in a bad state, or you need a clean start at any point:

```bash
make reset
```

This destroys all containers, rebuilds them, and re-plants the implants. Your
work in `workspace/` (`triage.yml`, `eradicate.yml`, reports) is preserved —
only the lab state is reset.

---

## PHASE 1: Triage the Fleet

> You cannot eradicate what you have not proven exists. Build a
> read-only recon playbook that catalogues every implant on every node into a
> structured report ARIA can verify — including a secret that can only be
> read live.

### What You Are Building

You will fill in `workspace/triage.yml` — a playbook with (at least) two
plays: one that gathers evidence from the fleet, and one that renders that
evidence into `reports/triage-report.yml`.

### Step 1.1 — Understand the Objective

For each of the four IOCs, you need a way to detect its presence on a node
and register the result:

| IOC | How to detect it |
|-----|-------------------|
| Cron implant | Does `/etc/cron.d/starfall-sync` exist? |
| Rogue beacon | Is `starfall-beacon.timer` enabled/active? |
| Root's extra key | Does `attacker@starfall-shadow` appear in `/root/.ssh/authorized_keys`? |
| Backdoor user | Does the `svc-telemetry` account exist? |

`ansible.builtin.command` (or `ansible.builtin.stat` for file existence)
registered with `changed_when: false` and `failed_when: false` is the
standard shape for a read-only probe whose exit code you want to inspect
rather than treat as a hard failure. Every probe task in this phase must be
non-mutating — ARIA checks that your triage run reports `changed=0` across
the fleet.

**The telemetry-id nonce.** The cron implant's file carries a hidden comment
of the form `# telemetry-id: <value>`, and the value is different on every
node. You cannot hardcode it or guess it — your report must contain the
*live* value read from each node during this run. A `command` task that
greps the cron file and captures the value (e.g. with `grep -oP`) is one way
to pull it out.

### Step 1.2 — Gather the Evidence

In the first play (`hosts: fleet`), write one or more tasks per IOC that
detect it and register a result. Once you have all four (plus the nonce),
assemble them into a single fact per host — `ansible.builtin.set_fact` is the
natural tool here, so the second play can read a clean, pre-shaped structure
out of `hostvars` rather than five separate registered variables per host.

### Step 1.3 — Render the Report

The report must be shaped like this, one block per host — see the full shape
in `triage.yml`'s header comment:

```yaml
triage:
  sdc-app:
    cron:
      found: true
      signature: starfall-sync
      telemetry_id: "<live nonce>"
    beacon:
      found: true
      signature: starfall-beacon
    authorized_key:
      found: true
      signature: attacker@starfall-shadow
    backdoor_user:
      found: true
      signature: svc-telemetry
  sdc-web: { ...same shape... }
  sdc-db:  { ...same shape... }
```

Render it **once**, on the control node, not once per fleet host. That means
a second play targeting `hosts: localhost`, with:

```yaml
gather_facts: false
become: false
```

on the play (or the equivalent per-task), so you don't need `sudo` to write
a local file. Use `ansible.builtin.copy` (with a Jinja `content:` block) or
`ansible.builtin.template` — either works. Inside it, loop `groups['fleet']`
and pull each host's assembled fact out of `hostvars[h]` to build the full,
multi-host report in one render.

### Step 1.4 — Run It

From `workspace/`:

```bash
ansible-playbook triage.yml
```

Check the result:

```bash
cat reports/triage-report.yml
```

Confirm all three hosts appear, all four categories are `found: true` with
the right `signature`, and each host's `telemetry_id` is a real value (not
blank, not the same across hosts).

### Step 1.5 — Run ARIA's Verification

```bash
cd ..
make test
cd workspace
```

ARIA re-runs your `triage.yml` itself (on the still-compromised fleet), then
checks: the report exists and is valid YAML; all four categories are
catalogued correctly on all three hosts; each host's `telemetry_id` matches
what ARIA independently knows to be true for that node; and your run
reported zero changes fleet-wide.

---

## PHASE 2: Purge the Implants

> Evidence gathered — now start removing. Take the cron job and the rogue
> beacon apart first: file, payload, unit, and the beacon's hook into nginx
> itself.

### What You Are Building

You will begin filling in `workspace/eradicate.yml`'s first play
(`hosts: fleet`) with the tasks that remove IOCs 1 and 2.

### Step 2.1 — Understand the Objective

**Cron implant**: delete both the cron drop-in and its hidden payload.
`ansible.builtin.file` with `state: absent` is the standard way to remove a
file — call it once per path (or loop over both paths with `loop:`).

**Rogue beacon**: this one has more moving parts. It's a `systemd` service +
timer pair, a hidden payload script, and — critically — a drop-in under
`/etc/systemd/system/nginx.service.d/` that makes nginx itself depend on the
beacon. All of it must go:

1. Stop **and** disable the timer (`ansible.builtin.systemd`, `state:
   stopped`, `enabled: false`) before deleting anything — removing unit
   files out from under a running/enabled service is the sloppy way to do
   this.
2. Delete the `.service` file, the `.timer` file, the hidden payload, and the
   nginx dependency drop-in — four separate paths, all removable the same
   way as the cron payload.
3. Run `ansible.builtin.systemd` with `daemon_reload: true` afterwards so
   systemd actually forgets the units you just deleted. Skipping this step
   is a common way to "remove" a beacon that systemd still half-remembers.

### Step 2.2 — A Note on Ordering

You do not need `serial: 1` for this phase — none of it touches the live web
service yet, and it can run in parallel across all three nodes safely. Save
the rolling, health-gated approach for the nginx *restart* in Phase 5 — that
is the one step that actually interrupts service.

### Step 2.3 — Apply and Verify

```bash
ansible-playbook eradicate.yml
```

```bash
cd ..
make test
cd workspace
```

ARIA checks (via a live probe inside each container, independent of your
inventory) that the cron file and its payload are gone, and that the beacon
timer is neither active nor enabled, its unit files and payload are deleted,
and the nginx dependency drop-in is gone too. It also checks that the C2
sink has stopped receiving check-ins from the fleet — which won't happen
until the beacon is fully stopped (Phase 4's firewall block reinforces this,
but the timer being dead is what actually silences it first).

---

## PHASE 3: Accounts, Keys & Creds

> The file-and-service layer is clean. Now close the access layer: the
> account the Operator provisioned, the key they planted, and the password
> they already know.

### What You Are Building

Continue adding tasks to the same `hosts: fleet` play in `eradicate.yml`.

### Step 3.1 — Understand the Objective

**Backdoor user**: `svc-telemetry` must be fully gone — the account *and* its
home directory (the equivalent of `userdel -r`), *and* the sudoers drop-in
that grants it passwordless sudo. `ansible.builtin.user` with `state: absent`
and `remove: true` deletes the account and its home in one task; the sudoers
drop-in under `/etc/sudoers.d/` is a separate file to remove with
`ansible.builtin.file`.

**Root's key**: remove the line containing `attacker@starfall-shadow` from
`/root/.ssh/authorized_keys` — without disturbing any other keys that might
be present. `ansible.builtin.lineinfile` with `state: absent` and a
`regexp:` matching the attacker's comment is built for exactly this: it
deletes only matching lines, leaving the rest of the file untouched.

**Root's password**: the leaked credential must be rotated, not merely
guarded by other defences. A `chpasswd`-style command per host, driven by
something that varies per node (so all three nodes don't end up with an
*identical* new password), is one way to do this — `ansible.builtin.shell`
piping into `chpasswd` is the direct route. Mark the task `no_log: true` so
the new credential never lands in your run output.

### Step 3.2 — Apply and Verify

```bash
ansible-playbook eradicate.yml
```

```bash
cd ..
make test
cd workspace
```

ARIA checks: the `svc-telemetry` account, its home directory, and its
sudoers drop-in are all gone on every node; the attacker's key is no longer
present in root's `authorized_keys`; and root's password hash on every node
no longer matches the leaked baseline hash it recorded at `make setup`.

---

## PHASE 4: Block the C2

> The implants are gone and the account is closed — but until you block the
> channel itself, any residual or future beacon has somewhere to call home.
> Cut it off, fleet-wide.

### What You Are Building

One more task (or small set of tasks) in the same `hosts: fleet` play:
a firewall rule dropping all egress from each node to the Operator's C2
sink.

### Step 4.1 — Understand the Objective

- Block **outbound** traffic to `172.30.0.20` — this is an egress rule, on
  the `OUTPUT` chain, not `INPUT`. The direction matters: you are stopping
  your own nodes from *reaching out*, not blocking something from reaching
  in.
- `ansible.builtin.iptables` with `chain: OUTPUT`, `destination: 172.30.0.20`,
  `jump: DROP` is the shape of this rule.
- Make it idempotent — running `eradicate.yml` a second time should not
  stack duplicate rules. `ansible.builtin.iptables` checks for an
  equivalent existing rule by default, as long as you keep the module
  arguments consistent between runs.

### Step 4.2 — Apply and Verify

```bash
ansible-playbook eradicate.yml
```

```bash
cd ..
make test
cd workspace
```

ARIA checks that a matching `DROP` (or `REJECT`) rule against 172.30.0.20
exists on the `OUTPUT` chain of every node, and that the C2 channel has gone
fully silent — no check-ins arriving at all, sampled over a short window.

---

## PHASE 5: Clean & Services Up (Capstone)

> Everything above this line can run safely in parallel — none of it touches
> the live web service. This phase is different. Removing the beacon's nginx
> dependency drop-in in Phase 2 means nginx's own unit configuration is now
> stale on disk. Until nginx is **restarted**, systemd is still holding the
> old, beacon-linked config in memory. That restart is unavoidable — how you
> sequence it across three nodes is the entire test.

### What You Are Building

A **second play** in `eradicate.yml`, separate from the fleet-wide cleanup
play above, that restarts nginx and confirms health before moving to the
next node.

### Step 5.1 — Understand the Trap

Each nginx restart takes a few seconds. If you restart it the "obvious" way —
one `ansible.builtin.systemd` task with `state: restarted`, run against
`hosts: fleet` with Ansible's default parallelism — all three nodes restart
**at the same moment**. For those few seconds, `sdc-app`, `sdc-web`, and
`sdc-db` are all down together, and the fleet's `/healthz` availability drops
to zero. Zero is below quorum (which needs at least two of three). That is
an outage you caused, and it fails this phase outright — regardless of how
clean the rest of your eradication was.

You solved this exact class of problem in **Mission 2.3**: restart one node
at a time, wait for it to prove itself healthy again, *then* move to the
next.

### Step 5.2 — Build the Rolling Restart

- A new play, `hosts: fleet`, with `serial: 1` — this is what forces Ansible
  to fully finish one host (all tasks in the play) before starting the next,
  instead of running all three in parallel.
- A task to restart nginx: `ansible.builtin.systemd`, `name: nginx`,
  `state: restarted`.
- A **health gate** immediately after: wait until the node's own
  `/healthz` endpoint is answering again before Ansible considers that host
  "done" and moves to the next one. `ansible.builtin.uri` (polling
  `http://127.0.0.1/healthz`, checking for `status_code: 200`, with `until:`
  / `retries:` / `delay:`) or `ansible.builtin.wait_for` are both suited to
  this — pick whichever you used in Mission 2.3.

### Step 5.3 — Why This Works

With `serial: 1` plus a health gate, only one node is ever mid-restart at a
time. The other two keep answering `/healthz` the whole time, so the fleet
never drops below 2-of-3 — quorum holds continuously, even though every
single node gets restarted in turn.

### Step 5.4 — Run ARIA's Final Verification

```bash
cd ..
make test
cd workspace
```

For this phase, ARIA arms a monitored segment, runs your **entire**
`eradicate.yml` exactly once, and latches the worst availability it observed
during that run. It checks: nginx was actually restarted on every node
(not just left running with a stale config); the fleet's availability never
dropped below quorum and had zero cumulative "blackout" time; and a full
re-scan finds every node completely clean — no implant, account, key, or
credential left over anywhere.

Because this phase measures a *live* run, re-testing against an
already-clean fleet won't produce a meaningful result — `make reset` before
a run you want scored end-to-end.

---

## MISSION COMPLETE — DEBRIEF CHECKLIST

Before closing this mission, confirm the following:

- [ ] `triage.yml` catalogues all four IOCs on every node, read-only (`changed=0`), including each host's live telemetry-id nonce
- [ ] `reports/triage-report.yml` is valid YAML shaped exactly as specified, one block per host
- [ ] `eradicate.yml` removes the cron job, its payload, the beacon unit/timer/payload, and the beacon's nginx drop-in, fleet-wide, with a `daemon_reload`
- [ ] `eradicate.yml` deletes the backdoor user (with home) and its sudoers drop-in, removes the attacker's root key, and rotates root's password, fleet-wide
- [ ] `eradicate.yml` firewall-drops all egress to 172.30.0.20 on every node, idempotently
- [ ] `eradicate.yml`'s nginx restart runs as a **separate, `serial: 1`, health-gated play** — never a fleet-wide parallel restart
- [ ] `make test` reports all five phases passing, including the fleet holding quorum through the restart

If any item is incomplete, return to the corresponding phase and complete it
before closing the mission record.

---

*SDC Cyber Command — 2187 — LIEUTENANT EYES ONLY*
