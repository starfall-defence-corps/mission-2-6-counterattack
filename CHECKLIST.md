# Mission 2.6: Counterattack — Progress Tracker

**Rank**: Lieutenant
**Arc**: Incident Response — Act 2 of 2 (Act 1 was [Mission 2.5: Noise Storm](https://github.com/starfall-defence-corps/mission-2-5-noise-storm))

Check each item off as you complete it. Run `make test` after each phase — it
re-scores both deliverables against all five phases. If a phase is blocked,
see `docs/HINTS.md`. Because eradication is graded on availability, a clean
scored run needs a freshly-armed fleet — `make reset` before a full pass.

---

## Phase 0: Boots on the Ground

- [ ] `make doctor` — machine is mission-ready
- [ ] `make setup` — fleet is online **and already compromised**
- [ ] Explored the scaffolding — `workspace/triage.yml` and `workspace/eradicate.yml` are both empty stubs (`tasks: []`)
- [ ] Confirmed a fresh `make test` fails every phase — that's expected, nothing is written yet

---

## Phase 1: Triage the Fleet

- [ ] `triage.yml` gathers all **four** IOCs per node, read-only (`changed_when: false` on every probe)
- [ ] Cron implant detected: `/etc/cron.d/starfall-sync`
- [ ] Rogue beacon detected: `starfall-beacon.service` / `.timer`
- [ ] Extra root `authorized_key` detected: comment `attacker@starfall-shadow`
- [ ] Backdoor user detected: `svc-telemetry`
- [ ] Each host's live **telemetry-id** nonce (from the cron implant's comment) is captured and written into the report — not guessed or hardcoded
- [ ] `reports/triage-report.yml` renders one block per host, shaped exactly as documented in `triage.yml`'s header comment
- [ ] ARIA: report generated, all four IOCs catalogued on every node, nonces match, recon made zero changes

---

## Phase 2: Purge the Implants

- [ ] `eradicate.yml` removes the cron job + hidden payload (`/usr/local/bin/.sync-agent`) fleet-wide
- [ ] Beacon timer stopped **and** disabled before deletion
- [ ] Beacon `.service`, `.timer`, payload, **and** the nginx dependency drop-in (`/etc/systemd/system/nginx.service.d/10-beacon.conf`) all removed
- [ ] `daemon_reload` run after removing the systemd units
- [ ] ARIA: cron purged, beacon unit fully purged, C2 callbacks ceased

---

## Phase 3: Accounts, Keys & Creds

- [ ] Backdoor user `svc-telemetry` removed with its home directory (`userdel -r` semantics)
- [ ] Its NOPASSWD sudoers drop-in (`/etc/sudoers.d/svc-telemetry`) removed
- [ ] Attacker's `authorized_key` (`attacker@starfall-shadow`) removed from root, fleet-wide
- [ ] Root's leaked password **rotated** on every node
- [ ] ARIA: backdoor user gone, root key gone, root credential rotated (hash differs from baseline)

---

## Phase 4: Block the C2

- [ ] Firewall rule drops all egress to `172.30.0.20` (the C2 sink), fleet-wide
- [ ] Rule is idempotent — re-running `eradicate.yml` doesn't stack duplicates
- [ ] ARIA: block rule present on every node, C2 channel stays silent

---

## Phase 5: Clean & Services Up (Capstone)

- [ ] nginx restarted on every node to apply the cleaned unit configuration
- [ ] Restart is **rolling** (`serial: 1`) behind a `/healthz` health-gate — never all three nodes at once
- [ ] Fleet never dropped below quorum (>=2 of 3 nodes serving `/healthz`) during remediation
- [ ] A full re-scan confirms every node is clean — no partial credit
- [ ] ARIA: web service restarted, fleet stayed available (`blackout_ms == 0`), full re-scan clean

---

## Verification

- [ ] `make test` — all five phases pass, fleet fully reclaimed
- [ ] `make submit` — work submitted for ARIA review

**Next stop**: [Master Simulation — Operation: Iron Curtain](https://github.com/starfall-defence-corps/master-simulation)
