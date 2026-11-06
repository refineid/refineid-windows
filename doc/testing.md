# Testing

How RefineID Windows is tested: what each tier proves, how to run it, and what
only a person with a card and a phone can check.

```powershell
pwsh scripts/test.ps1 -Tier fast      # Rust and contract tests
pwsh scripts/test.ps1 -Tier ui        # the built app, through UI Automation
pwsh scripts/test.ps1 -Tier all       # all of the above
pwsh scripts/test.ps1 -Tier coverage  # Rust coverage, target/llvm-cov/html
```

The script ends with passed, failed or not run for each tier, and exits
non-zero unless every tier passed. Reports land in `target/test-results`.

## Tiers

| Tier | Where | Proves | Needs |
| --- | --- | --- | --- |
| Unit | `#[test]` beside the Rust code | One unit's rules, against specification vectors | Nothing |
| Property | `proptest!` beside each parser | Any input read from the network, a pipe or a file is refused or read, never a panic | Nothing |
| Integration | `crates/*/tests` | The RAPP engine against the mock phone over real sockets | Nothing |
| Contract | `tests/RefineID.Contract.Tests` | The sides of a boundary agree: entry points, languages, markup | Source only, any host |
| UI | `tests/RefineID.Ui.Tests` | The real app opens, stays up, reports no failure and can be operated without a mouse | A free Windows desktop |
| Hardware | `scripts/test-*.ps1`, `scripts/test-browser-edge.py` | A real card and browser complete a login or a signature | A person, a card, a PIN |

The tiers form a pyramid: most checks are fast and need nothing, and only the
last needs a person. Prefer the lowest tier that can show the failure.

## Rules

- A bug fix starts with a test that fails without the fix.
- A test is deterministic. A timeout bounds a hang rather than making a test
  pass: `.config/nextest.toml` ends a test at four minutes, and retries none.
- A flaky test is a defect, fixed or filed the day it is seen.
- A test that cannot run here reports not run, never passed.
- Tests use synthetic identities and no real secrets (AGENTS.md).
- A parser of input from outside this process gets a property test.
- `#[ignore]` carries its reason, as the attribute's text.

## Isolation

- Every Rust test runs in its own process under `cargo nextest`.
- A UI test starts the Debug app with `LOCALAPPDATA` pointing at an empty
  temporary directory, so it never sees or changes the user's pairings, and
  removes it afterwards. An installed RefineID is left alone.
- PC/SC is not isolated: a card in a reader is really read, without a PIN. A UI
  test asserts only what holds with or without a card.
- `CurrentUser\My` is not isolated either, and the app installs and withdraws
  a paired phone's certificate there. A UI test therefore never pairs, and one
  checks that a run leaves the store as it found it.
- The pointer test moves the real pointer, and refuses to click unless the app
  is the foreground window. Leave the desktop alone while the UI tier runs.

## What runs when

- **Commit** (`.githooks/pre-commit`): format, lint, `refineid-lib-core` tests.
- **Push** (`.githooks/pre-push`): lockfile, rustdoc, every Rust test the host
  can run, contract tests.
- **Before a pull request** touching the app or a bridge: `-Tier all` on Windows.
- **Weekly** (`.github/workflows/ci.yml`): builds the app on Windows. It reports
  and never gates (working-method.md).

A change made on another host cannot run the Windows-only tests: run `-Tier all`
on Windows before merging it.

## Not automated

These need a person, or are not built yet:

- Login and signing with a real card, in a contact or contactless reader, and
  over a phone: the Hardware tier.
- The MSI and MSIX install and upgrade paths.
- UI flows that need a card present or a paired phone. The mock phone publishes
  no DNS-SD record, so the app cannot find it yet, and pairing changes the
  user's certificate store: this needs a disposable Windows user or machine,
  never a developer's own account.
- Coverage is reported and not enforced: a threshold rewards easy tests over
  the ones that matter.
- Coverage-guided fuzzing: `cargo-fuzz` needs a nightly toolchain, and this
  repository follows stable. The property tests cover the same borders with
  less depth.
