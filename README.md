# Starfall Defence Corps Academy

> 🧭 [← 2.5 Noise Storm](https://github.com/starfall-defence-corps/mission-2-5-noise-storm) · **You are here: 2.6 Counterattack** · [Master Simulation →](https://github.com/starfall-defence-corps/master-simulation) · [🏠 Academy Hub](https://github.com/starfall-defence-corps/sdc-academy)

> ☁️ **No Docker on your machine?** Create your own copy first (Use this template), then on **your** repo: **Code → Codespaces → Create codespace** — everything is preinstalled. First boot takes ~5 min (one-time); after that it starts fast.

## Mission 2.6: Counterattack

> *"The storm was noise. This is a foothold. Take it back node by node."*

An intruder has already planted persistence across the fleet — this is not a probe from outside, it is an occupation from within. Every node ships **already compromised**: a hidden cron job, a rogue systemd beacon phoning home, an extra key on root, and a backdoor account with passwordless sudo. Your job is incident response: find every implant, prove what you found, then remove all of it — without ever taking the scored web service dark while you do it.

You never touch the intruder's infrastructure directly. Everything you do is defensive automation, applied to **your** fleet.

## Prerequisites

- All of Module 1 (roles, variables, templates, firewalling) and Module 2 through **2.5 Noise Storm** (the serial/health-gate pattern from 2.3 Rolling Updates is the backbone of this mission's capstone, and this mission continues the incident begun in 2.5).
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (with Docker Compose v2)
- [GNU Make](https://www.gnu.org/software/make/)
- [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/) (`ansible-core`)
- Python 3.10+ (for the test environment) — on Debian/Ubuntu: `sudo apt install python3-venv`
- Git

> **Windows users**: run everything inside [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install), with Docker Desktop on the WSL2 backend.

## Quick Start

```bash
# 1. Use this template on GitHub (green button, top right) to create YOUR OWN
#    copy. Set it Public, then clone it:
git clone https://github.com/YOUR-USERNAME/mission-2-6-counterattack.git
cd mission-2-6-counterattack

# 2. Check your machine is mission-ready
make doctor

# 3. Bring the fleet online — it comes up already compromised
make setup

# 4. Activate the Python environment
source venv/bin/activate
```

5. **Read your orders**: [Mission Briefing](docs/BRIEFING.md)
6. **Work the incident**: [Exercises](docs/EXERCISES.md)
7. **Stuck?** [Hints & Troubleshooting](docs/HINTS.md)
8. **Track progress**: [Checklist](CHECKLIST.md)

## Lab Architecture

```
 Your Machine
+---------------------------------------------------------------+
|  workspace/           (the only place you write Ansible)       |
|    ansible.cfg                                                 |
|    inventory/hosts.yml         (the fleet, pre-registered)     |
|    triage.yml                  (find every implant, read-only) |
|    eradicate.yml               (remove them, keep the fleet up)|
|    reports/triage-report.yml   (you generate)                  |
|                                                               |
|  Docker Network: 172.30.0.0/24                                 |
|  +------------+  +------------+  +------------+   the fleet     |
|  | sdc-app    |  | sdc-web    |  | sdc-db     |   (you defend)  |
|  | .11  :2221 |  | .12  :2222 |  | .13  :2223 |                 |
|  +------------+  +------------+  +------------+                 |
|                                                               |
|  +-------------------------------+   range infrastructure      |
|  | sdc-noise  .20 (C2 sink)      |   (opaque — never touch it) |
|  | + .30 (uptime monitor)        |                             |
|  +-------------------------------+                             |
+---------------------------------------------------------------+
```

The three fleet nodes are yours to triage and clean. `sdc-noise` is opaque
range infrastructure with two jobs: it is the intruder's C2 sink (the implants
beacon out to it), and — from a separate monitor address — it watches every
node's `/healthz` and latches the worst availability it sees while you work.
You defend the fleet; ARIA reads the range's own telemetry to score you.

Only one SDC lab can run at a time — all missions share ports 2221-2223 and
subnet 172.30.0.0/24. Run `make destroy` in any other mission first.

## Available Commands

```
make help       Show available commands
make doctor     Check your machine is mission-ready
make setup      Deploy the compromised fleet + range (3 nodes, under intrusion)
make test       Ask ARIA to verify your triage + eradication
make reset      Destroy, rebuild, and re-arm the fleet + implants (fresh scored run)
make destroy    Tear down everything (containers, keys, venv, range state)
make ssh-app    SSH into sdc-app  (172.30.0.11)
make ssh-web    SSH into sdc-web  (172.30.0.12, runs nginx — the scored service)
make ssh-db     SSH into sdc-db   (172.30.0.13)
make submit     Submit your work for ARIA review (branch, commit, push, PR)
```

## Mission Files

| File | Purpose |
|------|---------|
| [BRIEFING.md](docs/BRIEFING.md) | Mission briefing — **read this first** |
| [EXERCISES.md](docs/EXERCISES.md) | Phase-by-phase operational instructions (5 phases) |
| [HINTS.md](docs/HINTS.md) | Troubleshooting and hints |
| [CHECKLIST.md](CHECKLIST.md) | Progress tracker |

## How ARIA scores this mission

`make test` runs **both of your deliverables** — `workspace/triage.yml` and
`workspace/eradicate.yml` — against the live, compromised fleet and reports
which of the five phases pass. Two things to know:

- **`make test` exercises the live lab.** It regenerates your triage report
  from a still-compromised fleet, then arms a monitored segment and runs your
  `eradicate.yml` exactly once, latching the worst availability it observes.
  Because eradication is graded on availability, a scored run needs a
  **freshly-armed** fleet — if you have already run `eradicate.yml` once
  (yourself or via `make test`), run **`make reset`** before testing again.
- **If every check shows as skipped**, the range is not armed — the fleet is
  already clean. Run **`make reset`** and test again. ARIA never scores an
  already-clean or offline range as a pass or a fail.

## ARIA Review (Pull Request Workflow)

**ARIA** (Automated Review & Intelligence Analyst) reviews your work two ways:

**Locally** — `make test` for instant pass/fail verification. No API key needed.

**On Pull Request** — push a branch, open a PR to `main`, and ARIA posts a
qualitative review as a PR comment. To enable it, add an `ANTHROPIC_API_KEY` repo
secret (**Settings → Secrets and variables → Actions**). Without a key, PR review is
skipped and `make test` still works locally.

## Troubleshooting

**Containers won't start**: Ensure Docker Desktop is running; check for port conflicts on 2221-2223 (only one SDC lab can run at a time — `make destroy` in any other mission first).

**`make test` shows everything skipped**: the range isn't armed (the fleet is already clean from a prior run) — `make reset`.

**`make test` fails with "No module named pytest"**: run `make setup` first — it builds the Python environment.

**Need a clean slate, or a fresh scored run**: `make reset` (rebuilds the fleet and re-arms the implants) or `make destroy` (full teardown).

**Docker network conflict** ("Pool overlaps..."): another Docker network is using 172.30.0.0/24 — stop it, or edit `.docker/docker-compose.yml`.
