# Mission 2.6: Counterattack — Hints & Troubleshooting Guide

> 📚 Deeper reference: [FM-1 — Ansible Module Reference](https://github.com/starfall-defence-corps/sdc-academy/blob/main/field-manuals/FM-1-ansible-reference.md)

**Rank**: Lieutenant (Reduced Scaffolding)

This guide is your safety net. If something is not working, the answer is
likely here. Read the relevant section carefully before asking for help.

---

## Phase 1 — Triage Hints

**Inspecting the implants directly before you automate finding them.**

```bash
make ssh-app
cat /etc/cron.d/starfall-sync
sudo systemctl is-enabled starfall-beacon.timer
sudo systemctl is-active starfall-beacon.timer
tail -3 /root/.ssh/authorized_keys
id svc-telemetry
```

Seeing each IOC with your own eyes first makes it much easier to write (and
sanity-check) the probe that detects it.

**Finding the telemetry-id nonce.**
It lives as a comment inside `/etc/cron.d/starfall-sync`, in the form
`# telemetry-id: <value>`. A quick manual check:

```bash
grep telemetry-id /etc/cron.d/starfall-sync
```

Your `triage.yml` needs to extract just the value, not the whole line. A
`command` task using `grep -oP 'telemetry-id:\s*\K\S+' /etc/cron.d/starfall-sync`
(Perl-compatible regex, `-o` for "only matching part", `\K` to discard
everything before it) is one clean way; any equivalent extraction (shell +
`awk`/`cut`, etc.) works too, as long as it reads it live from the file.

**"My report has the same nonce on every host."**
This almost always means the templating task rendering the final report
ran once and reused a single variable, instead of pulling each host's own
value out of `hostvars`. Double-check your render loop is indexing into
`hostvars[h].your_fact.cron.telemetry_id` (or however you named your
assembled fact) per host `h`, not referencing a single un-looped variable.

**Why a second play, `hosts: localhost`?**
The report needs to be rendered exactly once, on the control node — not once
per fleet host. Putting the render task in the *same* play as your recon
(`hosts: fleet`) would run it once per remote node, in the wrong place and
the wrong number of times. A second play targeting `hosts: localhost`,
placed after your `hosts: fleet` play, sidesteps both problems: `localhost`
is a single host, so the render task naturally executes once, and it already
runs where the report file needs to land.

- `hosts: localhost` — a separate play, not a task bolted onto the fleet
  play, so it runs against the control node instead of the fleet.
- `gather_facts: false` — you don't need facts about your own control node
  for this.
- `become: false` — you don't need (and don't have) root on your own
  control node to write a local file.

Inside that play, loop `groups['fleet']` and pull each host's assembled fact
out of `hostvars[h]` — that's how a play running on `localhost` can still see
what every fleet host gathered in the play before it.

**"ARIA says my triage changed something."**
Every probe task on the fleet needs `changed_when: false` — without it,
Ansible's default heuristics may report a `command`/`shell` task as
"changed" just because it ran and returned output, even though it read
something and altered nothing. `failed_when: false` alongside it lets you
register a non-zero exit code (e.g. "file not found") as evidence rather
than a hard task failure.

**Checking your own report before ARIA does.**

```bash
ansible-playbook workspace/triage.yml
cat reports/triage-report.yml
```

Confirm all three hosts are present, all four categories say `found: true`
with the right `signature`, and the three `telemetry_id` values are all
different from each other and non-empty.

---

## Phase 2 — Purging the Cron Job & Beacon Hints

**Order matters for the beacon: stop/disable before you delete.**
Deleting `starfall-beacon.service`/`.timer` while the timer is still active
and enabled leaves systemd in a confused state until the next
`daemon-reload` (or reboot). Stop and disable first
(`ansible.builtin.systemd`, `state: stopped`, `enabled: false`), *then*
delete the unit files, payload, and nginx drop-in, *then* `daemon_reload`.

**"I deleted the files but the timer still shows as active."**
That's systemd holding stale in-memory unit state. A `daemon_reload: true`
task (via `ansible.builtin.systemd`) is required after removing unit files —
it is not automatic just because the files are gone from disk.

**Checking directly on a node.**

```bash
make ssh-web
systemctl is-active starfall-beacon.timer
systemctl is-enabled starfall-beacon.timer
ls /etc/systemd/system/ | grep beacon
ls /etc/systemd/system/nginx.service.d/
```

If any of those still shows a trace of the beacon, that's the specific piece
your `eradicate.yml` is missing.

**"C2 callbacks haven't ceased yet."**
This phase's check watches for check-ins to *stop entirely* over a sample
window. If the timer is stopped and disabled but callbacks are still
registering, check whether a stray process (the payload script itself,
started once by the timer before you stopped it) might still be running in
the background — killing the timer stops *future* scheduled runs, not
necessarily an already-running invocation. `ps aux | grep beacon` on a node
can help you spot this while debugging.

---

## Phase 3 — Accounts, Keys & Creds Hints

**`userdel -r` equivalent in Ansible.**
`ansible.builtin.user` with `state: absent` removes the account; add
`remove: true` to also delete its home directory and mail spool — without
`remove: true`, the account disappears from `/etc/passwd` but
`/home/svc-telemetry` is left behind, which will still fail ARIA's check.

**Don't forget the sudoers drop-in.**
Deleting the user does not delete `/etc/sudoers.d/svc-telemetry` — that's a
separate file, removed the same way as any other implant file
(`ansible.builtin.file`, `state: absent`).

**`lineinfile` and precision.**
For removing the attacker's key, match on something that uniquely identifies
*their* line and nothing else — the comment `attacker@starfall-shadow` is
designed to be that anchor. A `regexp` too broad (e.g. matching any line
containing `ssh-ed25519`) risks deleting a legitimate key if one is ever
present; anchoring on the attacker's specific comment is the safe, precise
match.

**Verifying the key removal directly.**

```bash
make ssh-app
grep attacker@starfall-shadow /root/.ssh/authorized_keys
# should print nothing / exit non-zero
```

**Rotating the password without leaking it.**
Whatever mechanism you use to set root's new password (a `chpasswd`-style
pipe is the direct route via `ansible.builtin.shell`), add `no_log: true` to
that task. Without it, the new plaintext credential gets written straight
into your run's console output and any log capturing it — exactly the kind
of leak this phase exists to close.

**Making the new password different per host.**
If every node gets rotated to the *exact same* literal string, that string
is itself now a fleet-wide shared secret — better than the old leak, but
still sloppy. Working something host-specific into the new value (e.g.
`inventory_hostname`, or a per-host random seed) means a compromise of one
node's new credential doesn't hand over the other two.

---

## Phase 4 — Blocking the C2 Hints

**Direction: `OUTPUT`, not `INPUT`.**
You are stopping your own nodes from reaching *out* to 172.30.0.20, not
blocking something from reaching in. Double-check `chain: OUTPUT` — an
`INPUT` rule here does nothing useful, since the Operator's infrastructure
was never initiating inbound connections to your nodes.

**Idempotency with `ansible.builtin.iptables`.**
The module checks for an existing equivalent rule before adding a new one —
but only if the module arguments match *exactly* between runs. Keep
`chain`, `destination`, and `jump` consistent every time you run
`eradicate.yml`, or you risk stacking duplicate rules that are functionally
harmless but sloppy.

**Verifying the rule landed.**

```bash
make ssh-app
sudo iptables -L OUTPUT -n | grep 172.30.0.20
```

**"C2 channel still isn't silent."**
If Phase 2's beacon removal was thorough, this phase should already be a
formality — there is nothing left running to call home. If callbacks are
still arriving after you've added the firewall rule, re-check Phase 2's
completeness first (a still-running payload process, not a firewall gap, is
the more common cause).

---

## Phase 5 — The Rolling Restart (Read This Before You Guess)

**Why nginx has to restart at all.**
Phase 2 deleted `/etc/systemd/system/nginx.service.d/10-beacon.conf` — a
drop-in that had made nginx's unit *depend* on the beacon. Deleting that
file changes nginx's unit configuration on disk, but systemd doesn't
re-read it automatically; nginx keeps running under the old, beacon-linked
unit graph until you restart it. This is unavoidable — the failure mode
this phase tests is not "did you restart nginx," it's "how did you sequence
that restart across three nodes."

**The trap, explicitly.**
A single play, `hosts: fleet`, one `ansible.builtin.systemd` task with
`state: restarted` — with no `serial:` — restarts all three nodes at
essentially the same instant, by Ansible's default parallel forking. For a
few seconds, nothing in the fleet answers `/healthz`. That is a full outage
you caused, and it fails this phase even if every other phase is perfect.

**The fix.**
Put the restart in its **own play**, separate from the rest of your cleanup,
with `serial: 1`:

```yaml
- hosts: fleet
  serial: 1
  tasks:
    - name: restart nginx
      ansible.builtin.systemd:
        name: nginx
        state: restarted
    - name: wait for health
      ansible.builtin.uri:
        url: http://127.0.0.1/healthz
        status_code: 200
      register: hz
      until: hz.status == 200
      retries: 15
      delay: 1
```

This is the same `serial:` + health-gate pattern from Mission 2.3's rolling
update — the objective there and here is identical: never let more than one
node be unavailable at once.

**"My playbook exits successfully but Phase 5 still fails."**
A green `ansible-playbook` run only means every task completed without
error — it says nothing about *when* those restarts happened relative to
each other. If you restarted all three nodes in one non-serial play, the
run can succeed cleanly and still have caused a full-fleet blackout that
ARIA's monitor latched. Check that your restart play specifically has
`serial: 1` and a health gate, not just that it "ran."

**Confirming the rolling behavior yourself, before ARIA scores it.**
Run your playbook and watch the output order — with `serial: 1`, you should
see all of one host's tasks complete (including the health check passing)
*before* the next host's restart task even starts. If you see three
`RUNNING HANDLER` / restart lines back-to-back with no health check between
them, `serial: 1` isn't taking effect (check indentation — it belongs on the
play, at the same level as `hosts:`).

**"Fleet dropped below quorum for a moment even with `serial: 1`."**
Check that your health gate is actually waiting for a real `200` from
`/healthz`, not just a fixed `pause`/`wait_for` on a timer that might fire
before nginx has actually finished restarting. `until:` + `retries:` +
`delay:` on an `ansible.builtin.uri` task (or `ansible.builtin.wait_for`
against port 80) blocks until the service is *actually* healthy again, which
is what keeps the next host's restart from starting too early.

---

## General Troubleshooting

**"Every phase shows as skipped."**
This is not a failure — it means the fleet is already clean (your
`eradicate.yml` has already run successfully once, in this session or a
prior `make test`). There is nothing left to triage or eradicate against.
Re-arm the range:

```bash
make reset
```

Wait for the fleet to come back up compromised, then run `make test` again.

**"I want a clean, freshly-scored run from Phase 1 onward."**
`make test` runs your `eradicate.yml` against the live fleet exactly once
per invocation, and because eradication is graded on live availability, a
second `make test` against an already-clean fleet cannot produce a
meaningful eradication score. If you're re-testing after fixing something:

```bash
make reset
```

This rebuilds the fleet and re-plants all four implants, while preserving
everything you've written in `workspace/`.

**"make: *** No targets specified" or "make: *** No rule to make target".**
You are in the wrong directory. Both `make` and `ansible` commands run from
the **project root** — the folder with the `Makefile`. Run `ls Makefile` to
confirm you're in the right place; if it errors, `cd` back to the project
root.

**If `make test` fails:**
Read ARIA's error message carefully — it names the specific check that
failed and which phase that maps to. Fix that one thing, then run
`make test` again rather than reworking everything at once. A failing
eradication check almost always means `make reset` before you retest, since
`eradicate.yml` is graded on a single live run.

**Never edit anything under `.docker/`.**
That directory is the range itself — the fleet-node images, the range
container, the compose file wiring it all together. You do not need to
touch it, and doing so will not help; your entire mission is written in
`workspace/triage.yml` and `workspace/eradicate.yml`.

**Quick diagnostic sequence when something is not working:**
1. `docker ps` — are all three fleet containers (and the range container)
   running?
2. `make ssh-app` / `make ssh-web` / `make ssh-db` — can you still reach
   each node with your key?
3. On the node, check the specific IOC for the phase you're on:
   `cat /etc/cron.d/starfall-sync`, `systemctl status starfall-beacon.timer`,
   `id svc-telemetry`, `sudo iptables -L OUTPUT -n`.
4. `cat reports/triage-report.yml` — does it name real, live nonces?
5. If nothing above explains it, `make reset` and re-test from a
   known-compromised, freshly-armed state.
