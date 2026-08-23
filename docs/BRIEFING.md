---
CLASSIFICATION: LIEUTENANT EYES ONLY
MISSION: 2.6 — COUNTERATTACK
THEATRE: Starfall Defence Corps Academy
AUTHORITY: SDC Cyber Command, 2187
---

# OPERATION ORDER — MISSION 2.6: COUNTERATTACK

---

## 1. SITUATION

### 1a. Enemy Forces

The noise storm was cover. While the fleet's SSH and web ports were being
hammered from the outside, an intruder was already inside. Forensics now
confirm the fleet has been running compromised since before this mission
began. Designation: **THE OPERATOR**. Modus operandi: quiet, durable
persistence rather than continued noise — a hidden scheduled task, a rogue
background service disguised as part of the web stack, a spare key on the
most privileged account, and a second account nobody provisioned.

Four confirmed implants, planted identically on **every** fleet node:

1. A malicious cron job (`/etc/cron.d/starfall-sync`) running a hidden payload from `/usr/local/bin/.sync-agent`.
2. A rogue systemd beacon (`starfall-beacon.service` + `.timer`) that calls home to the Operator's infrastructure roughly every 10 seconds — and has attached itself to nginx's own unit configuration via a dependency drop-in, so it starts whenever the web service does.
3. An extra key in root's `authorized_keys`, tagged `attacker@starfall-shadow`.
4. A backdoor account, `svc-telemetry`, holding passwordless sudo via a drop-in under `/etc/sudoers.d/`.

Root's password itself must also be treated as compromised — it has leaked
and must be rotated, not merely left in place behind other defences.

The Operator's infrastructure is opaque range infrastructure. You will never
see its code or its container. You cannot script against it, disable it, or
negotiate with it. You can only observe what it does to your fleet — the
callbacks it receives — and respond.

### 1b. Friendly Forces

The **Starfall Defence Corps (SDC)** fleet — three nodes, `sdc-app`,
`sdc-web`, and `sdc-db` — all compromised identically. `sdc-web` runs the
fleet's web service and is the one under live availability scrutiny: the
fleet is considered "up" as long as at least **two of the three nodes** are
answering health checks at any given moment.

### 1c. Attachments / Support

**ARIA** (Automated Review & Intelligence Analyst) remains assigned. ARIA
runs your own recon and remediation playbooks against the live fleet and
reports, phase by phase, whether the Operator's foothold is gone.

### 1d. Operational Tool

All operations will be conducted using **ANSIBLE** — *Automated Network for
Secure Infrastructure, Baseline Lockdown & Enforcement*. This is a defensive
engagement, full stop. Every task you write inspects, reports, or removes.
You will not write offensive code, and you will never interact with the
Operator's infrastructure directly — only observe its silence once you have
done your job.

---

## 2. MISSION

Triage the fleet: catalogue all four implants on every node, without
changing anything, and prove your findings in a structured report — including
a live, per-host secret that can only be read from a still-compromised node.
Then eradicate: remove every implant, delete the backdoor account, pull the
attacker's key, rotate the leaked credential, and sever the Operator's
command channel. Do all of this while the fleet's web service **never drops
below quorum** — not even for the few seconds it takes to apply a config
change.

**End state**: all three nodes clean of every implant, the backdoor account
gone, root's key and password no longer known to the Operator, all outbound
traffic to the Operator's infrastructure blocked — and the web service never
dark for a moment while you did it.

---

## 3. EXECUTION

### 3a. Commander's Intent

Two failure modes bookend this mission, and both are worse than doing
nothing. Triage that isn't read-only contaminates the evidence and may tip
off the Operator. Eradication that isn't careful about *how* it restarts the
web service can black out the fleet more thoroughly than the Operator ever
did — a cure worse than the disease. The skill this mission tests is not
"can you write tasks to delete files." It is "can you sequence irreversible
changes to a live, scored service without an outage." You have done this
before, in Mission 2.3. Bring that discipline here.

### 3b. Concept of Operations

Five sequential phases. Complete each phase before advancing. Full procedural
detail is in **EXERCISES.md**.

| Phase | Task | Objective |
|-------|------|-----------|
| 1 | Triage the Fleet | Catalogue all four implants per node into a verifiable report, read-only |
| 2 | Purge the Implants | Remove the cron job and the rogue beacon (unit, timer, payload, nginx drop-in); silence the C2 |
| 3 | Accounts, Keys & Creds | Delete the backdoor account, pull the attacker's key, rotate root's password |
| 4 | Block the C2 | Firewall-drop all egress to the Operator's infrastructure, fleet-wide |
| 5 | Clean & Services Up | Restart the web service to apply the cleaned config — without ever dropping below quorum |

### 3c. Fleet Assets

All nodes are accessible via SSH. Credentials are uniform across the fleet.

| Designation | Role | IP Address | SSH Port |
|-------------|------|------------|----------|
| `sdc-app` | Fleet Application Node | 172.30.0.11 | 2221 |
| `sdc-web` | Fleet Web Server (scored service) | 172.30.0.12 | 2222 |
| `sdc-db` | Fleet Database Server | 172.30.0.13 | 2223 |

**SSH User**: `cadet`
**Authentication**: SSH key located at `workspace/.ssh/cadet_key`

The Operator's infrastructure sits at `172.30.0.20` — this is the address you
block, and never anything you touch directly.

### 3d. Rules of Engagement

- This is a **defensive engagement only**. You write and apply Ansible
  against your own fleet — never against the Operator's infrastructure.
- Do not modify anything under `.docker/` — that is range infrastructure, not
  fleet infrastructure. Your work lives entirely in `workspace/`, in exactly
  two files: `triage.yml` and `eradicate.yml`.
- Triage must be **read-only**. Every probe task must leave `changed: 0` on
  every node — you are gathering evidence, not altering the crime scene.
- Eradication must be **complete on every node**. A fleet with two nodes
  clean and one still compromised is not clean — there is no partial credit.
- The web service must **never drop below quorum** while you remediate.
  Restarting it is unavoidable — the beacon's nginx dependency drop-in means
  nginx's own configuration is dirty and must be reloaded — but *how* you
  sequence that restart across three nodes is the difference between a pass
  and a fleet-wide outage.
- All findings are to be reproducible. If ARIA cannot verify your work, your
  work is not complete.

---

## 4. SUPPORT

| Resource | Function | Command |
|----------|----------|---------|
| **ARIA** | Verifies mission compliance; reports pass/fail per phase | `make test` |
| **HINTS.md** | Operational guidance if mission stalls | — |
| **Fleet Reset** | Rebuilds the fleet and re-plants the implants | `make reset` |

Run `make test` after each phase. Note that `make test` exercises **both
deliverables against the live fleet** — it regenerates your triage report
fresh and then runs your `eradicate.yml` exactly once against an armed,
monitored segment. Because eradication is graded on live availability, a
clean scored run needs a freshly-compromised fleet — use `make reset` before
a run you intend to be scored end-to-end.

If ARIA ever reports every check as skipped, this is not a failed phase — it
means the fleet is already clean from a prior run and there is nothing left
to eradicate. Run `make reset` and try again.

Consulting **HINTS.md** is authorised at Lieutenant rank. Using available
intelligence is not weakness — it is doctrine.

---

## 5. COMMAND AND SIGNAL

**Reporting**: ARIA is your automated reporting chain. Her output is your
after-action record.

**Commander's Final Order**: This mission does not end until every implant is
gone from every node, the backdoor account is deleted, the attacker's key and
the leaked password no longer grant access, the command channel is silent —
and the web service held quorum the entire time you took the fleet back. No
exceptions.

Proceed to **EXERCISES.md** for phase-by-phase operational instructions.

---

*SDC Cyber Command — 2187 — LIEUTENANT EYES ONLY*
