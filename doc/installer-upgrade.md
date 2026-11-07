# Installer upgrade and cleanup

Installing a RefineID Card Driver package leaves exactly that build on the
machine: no earlier package, and nothing an earlier development install or
earlier build wrote that this build cannot use. This file says how the
package (`crates/refineid-msi`), the Card Module's custom actions, the
development installer (`scripts/install-dev.ps1`) and the pairing store
achieve that, and what they leave alone.

## Package identity

- **UpgradeCode** `{DBD5521A-AA2C-45D1-B79C-8535E2C262A5}` is the one
  authored identifier and has never changed (`crates/refineid-msi/src/main.rs`).
  Windows Installer finds every earlier package by it.
- **ProductCode** and **PackageCode** are derived from it (RFC 4122 version 5)
  over the build stamp and a SHA-1 of the payload files. Two builds with
  different files are different products, even with one stamp; the same
  files rebuilt give the same codes, so the second install of an identical
  package is a repair, not a second product.
- **ProductVersion** is the build stamp `YY.M.D.HHMM` (UTC, `HHMM` = hour ×
  100 + minute; `packaging/windows/build-msi.ps1`, `crates/refineid-stamp`)
  folded into the three fields Windows Installer compares:
  `YY.M.(D × 1000 + slot)`, the slot being the minute of the day scaled to
  0–999 (`Version::product_version`). Builds two minutes apart always get
  distinct, ordered versions.

## Upgrade: every newer build replaces the installed one

The `Upgrade` table has two rows for the package's UpgradeCode:

| Range | Attributes | Property | Effect |
|---|---|---|---|
| `0.0.0` to this version, both inclusive | min and max inclusive | `OLDERVERSIONBEINGUPGRADED` | removed by `RemoveExistingProducts` |
| above this version | detect only | `NEWERVERSIONDETECTED` | install refused |

- The removing range includes the package's own version, so a rebuild in the
  same version slot (same ProductVersion, other ProductCode) replaces the
  earlier one. `FindRelatedProducts` runs only on the first install of a
  ProductCode, so a package never removes itself.
- `FindRelatedProducts` runs at sequence 25, before `LaunchConditions` at
  100, in both the UI and the execute sequence: the downgrade guard is the
  launch condition `NOT NEWERVERSIONDETECTED`, with the message
  "A newer version of RefineID Card Driver is already installed."
- Both properties are listed in `SecureCustomProperties`, so an
  installation started from a user's session (double-click, UAC prompt)
  passes the products it found to the elevated part that removes them.
- `RemoveExistingProducts` runs right after `InstallInitialize`: the
  earlier package is uninstalled completely, its own uninstall custom
  actions included, before any file of the new one is laid down.

## Uninstall removes what the package wrote

| What | How |
|---|---|
| `System32\refineid_minidriver.dll`, `Program Files\RefineID\refineid-agent.exe`, and the driver package's INF and catalog | `File` rows of the package's components |
| The Calais registrations the package authors (`crates/refineid-msi/src/cards.rs`) | their `Registry` values, and a `Registry` row with name `-` per key, which removes the key with every value and subkey |
| Every other Calais registration whose `80000001` names `refineid_minidriver.dll`, in both registry views | the Card Module's `RefineIdRemoveCardRegistrations` (`crates/refineid-minidriver/src/card_registrations.rs`), before the files go |
| The `RefineIDAgent` value under `HKLM\...\CurrentVersion\Run`, which starts the agent at every sign-in | its `Registry` row |
| The `RefineID Key Storage Provider` CNG registration | `RefineIdUnregisterKeyStorageProvider` |
| The driver package in the driver store | `RefineIdUninstallCardDriver` |
| `SCardSvr` | stopped and started again, so the card database is reread |

## Installing removes what installations outside the package left

Development installs (`scripts/install-dev.ps1` before this change, and its
earlier revisions) wrote outside any package. On a first installation of
its ProductCode, a fresh one or an upgrade, the package removes:

- **The System32 Card Module copy.** A `RemoveFile` row deletes
  `System32\refineid_minidriver.dll` before `InstallFiles`. Windows
  Installer otherwise keeps an unversioned file whose modification date is
  later than its creation date as the user's own, and a copied DLL usually
  has such dates.
- **Calais registrations of this module the package does not author**
  (`FINEID-Dev-CCID`, `FINEID-S4-1-v4.0-contactless`,
  `FINEID-RAPP-Virtual`, and any other). `RefineIdRemoveCardRegistrations`
  runs deferred as `LocalSystem` after the files are in place and before
  `WriteRegistryValues`. It deletes every registration whose `80000001`
  names `refineid_minidriver.dll`, bare or at the end of a path, in any
  case, in the 64-bit and the 32-bit view; then the package writes its own.
  Ownership is that value alone: another vendor's registration names
  another module and is never touched. The action has no undo, and a repair
  does not run it, because a repair need not rewrite the registrations.
- **The development backup** `ProgramData\RefineID\backup\refineid_minidriver.dll`,
  with its folders when empty (`RemoveFile`, on install and uninstall).
- **The development event source**
  `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\RefineID`
  (`RemoveRegistry`). Release builds never log.
- **The key storage provider** of a development install has the same name
  and the same image, `refineid_minidriver.dll`, so the package's
  registration takes it over (`CRYPT_OVERWRITE`) and its uninstall removes
  it.

### Files in use

The Card Module is loaded by every process that uses a card or the key
storage provider (browsers, `lsass`, `certutil`). Windows Installer cannot
delete a loaded DLL. It moves the old copy to `C:\Config.Msi\<name>.rbf`,
installs the new file in its place at once, and deletes the moved copy when
Windows restarts (`PendingFileRenameOperations`, log message 1903). Every
process started after the installation loads the new module; a process
that had the old one loaded keeps it until it exits. The agent runs in
each signed-in user's session, so its file is in use in the same way: the
upgrade replaces it, the running agent keeps the earlier build until the
user signs out, and the next sign-in starts the new one. The installation
still reports success (exit code 0): nothing of the new build waits for
the restart. Windows Installer's Restart Manager may also close and
restart applications in the installing session that hold a file the
package replaces. The development installer renames a loaded copy beside
itself and deletes it at restart with
`MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`, and says so.

## Per-user state

A per-machine package does not reach into user profiles. The protected
pairing store (`crates/refineid-windows-credential-store/src/pairing.rs`)
judges `%LOCALAPPDATA%\RefineID` at every load, and the agent loads it
at every sign-in:

- `agent.log` (a log of builds that logged), `pairing-set.lock` (an
  unreleased build's lock file) and `bin\` (agent copies outside Program
  Files, which the pipe client refuses) are removed.
- A stored pairing record of a superseded revision is refused and the set
  is written back without it, as before. Revision 10 and earlier records
  could hold the card's authentication certificate; revision 11 holds none,
  so a pairing made by an earlier build is paired again.
- A stored set this build cannot decode is deleted with its card sightings,
  unless it is of a revision above this build's: a later build wrote it,
  and a downgrade keeps it for that build. A set DPAPI cannot unprotect is
  kept: that may be a profile whose keys are not loaded, not a format.
- In both cases the store leaves the empty file `earlier-pairing-removed`.
  While it is there and nothing is paired, the app shows "The pairing was
  made with an earlier RefineID. Pair again." in place of "No phone is
  paired with this device."; storing a pairing removes it.
- Kept: `pairing-set.dpapi` of the current format, `card-sightings`,
  `trusted-lists`, `ca-certificates`, and the development app's
  `dev-errors-cleared`.

## Development installs

`scripts/install-dev.ps1` never leaves a development install beside a
package. Before it installs it uninstalls every product of the UpgradeCode
(`msiexec /x /qn`) and removes what any earlier development install left,
by the same ownership rule as the package. `-Uninstall` does only the
removal. A Card Module a process has loaded is renamed beside itself and
deleted at restart. `scripts/uninstall-dev.ps1` is replaced by
`install-dev.ps1 -Uninstall`.

## Not touched

- Calais registrations of other vendors' Card Modules.
- Certificates in any store. The roots and issuing CAs that Windows
  propagated from earlier builds' `msroots` file, and card certificates in
  `CurrentUser\My`, are handled by the Card Module's own root removal and
  the agent, which removes a card's entries when the card leaves
  (`crates/refineid-minidriver/README.md`,
  `doc/stpa-windows-ble-requester.md` W-R-22).
- The RefineID app's MSIX package: Windows replaces it by its package
  identity when a newer version is installed.
- Files under `%LOCALAPPDATA%\RefineID` no RefineID build wrote, such as a
  developer's Python environment for the browser tests.

## STPA

Losses and hazards are the RAPP record's (refineid-core
`doc/security/stpa-rapp.md`). The controllers are Windows Installer acting
on the package's tables, the Card Module's cleanup action, the development
installer, and the pairing store; their feedback is what is registered and
stored on the machine.

| UCA | Hazard | Constraint |
|---|---|---|
| UCA-1: An upgrade installs beside the earlier product instead of replacing it, so two builds answer for one card or two agents run. | H-5 | CC-1: every newer package removes the installed one before it installs (`Upgrade` table, `SecureCustomProperties`, `RemoveExistingProducts` first). |
| UCA-2: An older package installs over a newer one, putting back code with defects the newer build fixed. | H-1, H-5 | CC-2: the downgrade is detected before the launch conditions and refused. |
| UCA-3: A card stays bound to a registration that no installed package owns, or to an old module copy, after install or uninstall. | H-3, H-5 | CC-3: the package removes every registration naming its module, and replaces the System32 copy whatever its dates. |
| UCA-4: The cleanup removes another vendor's registration, so that vendor's cards stop working. | L-3 | CC-4: a registration is removed only when its `80000001` names `refineid_minidriver.dll`. |
| UCA-5: A pairing set this build cannot read stays, so every load fails and the user is not told to pair again. | H-5, H-7 | CC-5: an unreadable set no later build wrote is removed, and the user is told to pair again until a pairing is stored. |
| UCA-6: A pairing a later build wrote is removed by an earlier one. | H-7 | CC-6: a set of a later revision is kept. |
