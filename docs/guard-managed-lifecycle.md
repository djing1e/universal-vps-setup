# Managed Guard install/update v0.1

This stage connects the Guard release receipt to its narrow install/update
transactions. It covers only the current pinned executable and two unit files.
The release ID remains 1.0.0-rc.1; no engine/configuration migration is introduced.

## Installation

`guard_managed_install.py check --bundle DIR` accepts only a verified complete
bundle (engine, service, timer) and either a clean host or a fully recognized
current installation. Cached/transient units with absent disk files, partial or
custom installations and unknown/drifted receipts refuse changes. Check is read-only.

`install --bundle DIR --confirm INSTALL-GUARD-OBSERVE` uses the shared lock and
refuses pending transactions. On a clean host it atomically creates the three
root-owned files without replacing existing paths, reloads systemd, enables the
Guard timer and verifies both observer commands. Only then does it atomically
record managed_install provenance. Errors remove only the exact newly created
files/receipt and disable the newly installed timer; ambiguous recovery is explicit.
A pending install record after a crash requires manual recovery.

For an already current but unregistered installation, this action records metadata
only and preserves existing enabled/active states. A current registered installation
is a noop. Reinstalling never serves as an implicit enable operation for a disabled
existing timer. Legacy installer/drop-in migration remains a separate compatibility
path; this new path refuses overrides instead of silently migrating them.

## Engine updates

The updater now validates existing registration before any service changes.
Unregistered recognized legacy engines can be upgraded to the pinned release after
explicit confirmation. A managed_update receipt is written only after new-engine
and timer verification. The previous raw receipt, if present, is included in the
backup and its presence is recorded in the transaction. A metadata write/verification
failure rolls back the engine and restores the exact previous receipt, including
absence. An externally changed receipt is not overwritten; recovery_required blocks
further operations. Noop preserves the receipt byte for byte and does not register
an otherwise current unregistered installation.

The current release catalog does not describe migration between different registered
release versions: unknown/older registrations are refused until their migration is
explicitly described. A receipt does not override content or state checks. Versioned
configuration migration, general component updates and remove integration are not
part of this stage. Legacy remove keeps the receipt; Audit then reports drift/review.

## Validation scope

Tests use private roots and fake systemd for file transactions, receipt failures
before/after creation, restore, preserved disabled state and unknown-state refusal.
The real-systemd update fixture uses its own private test receipt, not the host's
registration. It verifies that the host's original receipt remains unchanged.
Real fresh-install systemd validation is a separate test before release; ordinary
checks on an already registered host intentionally return noop.


## Menu

16 -> 6 -> 1 uses the managed installer, not the compatibility Bash installer.
It first checks and requires INSTALL-GUARD-OBSERVE only for a fresh installation
or metadata-only registration. Items 5/6 use the registry-aware engine updater.
The nine-file bundle (installer, updater, policy, registry/catalog, inventory helper,
engine and two unit artifacts) is pinned to one reviewed commit and all hashes
are checked before Python execution. Already current registered installations
return noop for install/check/update, without confirmation or service controls.
Old pinned bundles remain immutable; old registry readers can conservatively
report newer managed provenance as unknown and should be replaced by the new bundle.
