# Guard engine-only upgrade v0.1

This is a separate opt-in transaction for the Auto Abuse Guard observer executable.
It is not a general apply command for the advisory planner. It does not accept an
old Audit as permission to write: preflight reads the current files and effective
systemd state directly and repeats the checks after stopping only this observer.

Supported hosts are Debian 13 and Ubuntu 24.04; unknown OS state refuses the operation.

The default command is `check --candidate PATH`. Check reads files and calls only
`systemctl show`; it creates no backups/locks and stops or starts nothing. The
candidate must be the exact pinned engine in guard_engine_policy.json. The installed
engine must match an accepted release hash, be root-owned, mode 0755, a regular file
with one hard link and no symlink path components. Both unit files must match the
pinned installer templates, resolve from /etc/systemd/system, have no effective
drop-ins and no pending daemon reload. Unknown/custom/failed states refuse the update.
These checks establish a narrow reviewed release layout, not general resource ownership.

Apply requires root and `--confirm UPDATE-GUARD-ENGINE`. The candidate is supplied
locally; this tool never downloads anything. Recheck the tool, policy and candidate
checksums from the same reviewed commit before running it.

```bash
clear
python3 lib/guard_engine_upgrade.py check --candidate modules/xtls-auto-abuse-guard.py
```

When current and target engine hashes match, apply returns noop without stopping
services or creating backups. It acquires the existing installer lock, so it must
not run concurrently with the installer. No artificial upgrade is required on an
already current production node.

For a recognized older engine, apply:

1. Acquires the installer's lock and refuses unresolved previous transactions.
2. Creates a private backup under /var/lib/xtls-safe-upgrade with the old executable,
   unchanged unit copies, original timer state and a pending transaction record.
3. Stops only xtls-auto-abuse-guard.timer and its oneshot service, then rechecks.
4. Atomically replaces and fsyncs only the executable, retaining root:root/0755.
5. If the timer was active, runs the existing systemd service (both scan and
   behavior-record, with existing resource limits) and checks Result/ExecMainStatus.
   An inactive timer remains inactive, is not enabled, and receives static/hash
   verification only. A scan may append normal Guard observations/history.
6. Restores the timer's prior active state, checks enablement stayed unchanged and
   records committed.

On errors after quiescing, rollback stops only the same observer, restores the old
executable atomically, verifies its hash, runs the old scan if the timer was active,
restores/checks timer state and records rolled_back. Unit files, configuration and
history are never replaced or rewound. There is no schema migration in this tool.
An externally changed executable is never blindly overwritten during rollback.
Failure to restore is reported as recovery_required with the backup path, not success.
A process/host crash may leave pending: later applies refuse until manual recovery.
No guarantee of automatic recovery across power loss is made.

Docker, Remnanode/Xray, web servers, databases, DNS, SSH, routes, firewall rules,
installed units, timer enablement and persistent Guard configuration are not targets.
This stage is CLI-only; the main menu and planner's apply_available=false stay unchanged.

## Disposable VM integration

`tests/run_guard_upgrade_systemd.py` is a separate explicit fixture for a disposable
vm1-xtlspro with real systemd as PID 1, no active Docker/Remnanode and no Remnanode
paths. It requires `--confirm TEST-VM-GUARD-UPGRADE` and a current enabled/active Guard
installation. Never run this on a production node. This fixture actually changes
the Guard executable and temporarily disables its timer in the disabled-state case.

The fixture uses in-memory test policy hashes: two copies of the current observer
with different comments force a replacement, and a separate Python candidate exits
73 to test rollback through real systemd. The production policy file is unchanged.
A forked updater exits immediately after stopping the real timer to exercise the
pending transaction gate; this is a process-interruption checkpoint, not a power-loss
or filesystem-durability test. Success, rollback, disabled/inactive and interrupted
transaction scenarios print separate PASS lines. A finally block restores the
original engine, verifies unchanged units and restores enabled/active timer state.
Artifacts remain in a private /root/xtls-guard-systemd-test.* directory, including
an archived pending record; it is not falsely relabeled committed. SIGKILL of the
fixture itself or host power loss can prevent finally cleanup and require manual
recovery from those artifacts. The fixture never calls Docker, firewall or network
configuration commands.

Before verification scans of a candidate or restored engine, the transaction runs
systemctl reset-failed for xtls-auto-abuse-guard.service only. This clears that
unit's failure/start-rate counter so a failed candidate cannot exhaust the old
engine's restart budget during rollback. The unit's configured rate limits are
unchanged. Preflight still refuses an already failed service; check/noop do not
reset failures or start anything. Repeated disposable-VM scans exposed this case
through real systemd's "Start request repeated too quickly" diagnostic.

An inactive unit may be garbage-collected after its timer is disabled. If reset-failed
returns the exact C-locale "Unit xtls-auto-abuse-guard.service not loaded." diagnostic,
verification revalidates the effective unit path/drop-ins/reload state and requires
ActiveState=inactive before starting it. Other reset errors, timeouts, unknown units
and active-unit mismatches remain failures. An unloaded unit has no remaining
start-rate counter; the reset is not needed in that specific case.


## Menu integration

In 16 -> 6 (Auto Abuse Guard), item 5 checks engine updates and item 6 checks,
then offers an explicit UPDATE-GUARD-ENGINE confirmation only for a recognized
older engine. Both return early on noop without confirmation, backup or service
stops. Declining or EOF cancels the update. Errors return to the Guard menu.
The existing install/remove/status/scan items retain their numbers.

The wrapper stages the updater, policy, inventory helper and engine candidate
from an immutable reviewed commit, verifies all four SHA256 hashes before executing
any Python code, and cleans the private temporary bundle on exit. The apply command
revalidates current state under its lock after confirmation. It does not use the
previous check JSON as authority. The main menu does not run the disposable-VM
fixture or modify release policy. A displayed verification=service_scan describes
the verification that a real active-timer update would perform; check never runs it.
