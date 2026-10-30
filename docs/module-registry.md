# Module registration v0.1

This stage records the release and a narrowly defined resource set for Auto Abuse
Guard only. It does not install/update modules, edit units/configuration, start
services or enable timers. The main menu, installer and engine updater are unchanged.

module_releases.json assigns version **1.0.0-rc.1** to the pinned existing Guard
executable and its two exact unit templates. This is the first registry release
identifier, not a version read from the executable or an existing Git tag. The
source revision and all three SHA256 hashes are recorded. Unit modes 0600 and 0644
are recognized because the existing installer inherits the operator's umask; the
executable must be 0755. Files must be root:root regular files without symlink path
components or multiple hard links. No private infrastructure data is in the catalog.

`python3 lib/module_registry.py inspect` reads these resources and any registration.
It writes nothing and does not probe or start systemd. Inventory Audit now includes
the same observation under component_registry. Missing/broken catalog/helper data
becomes unknown rather than allowing an update. Existing pinned old Audit downloads
and Guard update bundles are unaffected by this new optional Audit field.

| Status | Meaning |
| --- | --- |
| recognized_unregistered | All three files match the catalog, but no management record exists |
| registered_matches | A protected explicit-adoption record matches both the catalog and current resources |
| registered_drift | A recognized record exists but current content/metadata differs |
| unknown | Missing/custom/unreadable resources or an invalid/untrusted record need review |

Content recognition never creates a registration. For a known legacy installation,
registration is a separate root-only action:

```bash
clear
python3 lib/module_registry.py adopt --confirm ADOPT-AUTO-ABUSE-GUARD
```

Adoption takes the existing Guard installer/updater lock. It checks all resources,
then uses only systemctl show to verify the effective units: known loaded path,
no drop-ins, no pending reload and known nonfailed runtime/enablement states.
An inactive/disabled timer stays inactive/disabled. Unknown states refuse adoption.
A private root:root/0600 JSON record is created atomically without replacing an
existing record at /var/lib/xtls-vps-manager/components/auto-abuse-guard.json; the
manager and components directories must be root:root/0700. The record contains the
release ID, source revision, exact file hashes/modes/UID/GID, registration time and
explicit_adoption provenance. Repeating adoption on a matching record is a noop.

Corrupt, unsafe, unknown-version or changed records are never repaired/overwritten
automatically. Recorded resource paths must be exactly the catalog whitelist;
registration JSON cannot cause arbitrary paths to be read. Drift requires manual
review, not reconciliation. Adoption and Audit are not atomic snapshots of all
system resources; an external concurrent edit can make final verification fail.

This record is a local administrative declaration, not cryptographic proof of
historical ownership, whole-system health or permission to overwrite local settings.
It covers exactly three files: no history, configuration directories or firewall
resources. automatic_update remains false and the planner's manual review gate stays
closed. Future installation/update/remove integration and registry migrations need
separate changes before the registry can participate in broader managed updates.
