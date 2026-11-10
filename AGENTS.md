# RefineID Windows agent rules

- Source and project prose may use the ISO-8859-15 character repertoire,
  including meaningful specification symbols such as `§`; do not degrade them
  to ASCII. Store each source file in the encoding required by its toolchain
  (Rust `.rs` files must be valid UTF-8). Preserve a protocol fixture's exact
  specified byte encoding.
- No AI attribution in commits.
- New source files carry `Copyright 2026 Petri Koistinen` with no
  email address and HTTPS license URLs; shell scripts carry the
  one-line form under the shebang, PowerShell keeps its multi-line
  form.
- Zero PIN and PIN-length logging across all environments: Never log, trace,
  display, or format PIN bytes, candidate PIN lengths (e.g. `got {len}`), or
  development PIN identifiers in log sinks, audit records, or error strings.
  Never commit test PINs or card secrets.
- The CAN is a secret like the PINs: never displayed back, logged (digits or
  length), sent over RAPP or diagnostics, or read from argv or the
  environment. Entry hides it by default with a reveal control. A personal
  card's CAN is stored only in the DPAPI-protected credential store
  (refineid-core `doc/security/credential-custody.md`).
- Development builds make every error visible; release builds never log. A
  debug build (`debug_assertions` in Rust, `DEBUG` in C#) reports each
  failure at its typed boundary with `refineid_dev_errors::report!` or
  `DevErrorLog.Report` to the Windows Event Log (Application log, source
  `RefineID`), and the app's Log window shows it as it arrives. A report
  names the event and its cause: an error case, a fixed text or a
  spec-named status, never a value it carries, except a failed
  session's report, which also names the paired device's
  display label and its transport. Release, Store and
  production builds contain no logging code: no sink, no Event Log call,
  and no stderr, debugger or file log.
- Safe Rust owns protocol, parsing, and secret handling. Keep `unsafe` inside
  the Windows Card Module or PC/SC boundary.
- Every Windows ABI pointer access must validate nullability and length before
  dereferencing.
- No Magic Codes - define everything (see [Types and numbers](#types-and-numbers)).
- Verify claims from Microsoft, DVV, ICAO, eIDAS, or another primary source.
- On Windows, run `scripts/setup-dev-tools.ps1` before building (see
  `doc/toolchain.md`). It installs the toolchain and keeps Visual Studio and
  every SDK at the latest release. Rust follows the latest stable release
  (`rust-toolchain.toml` selects the stable channel); never pin a release.
- Always run formatting (`cargo fmt`, `csharpier`), clippy (`-D warnings` on both host and Windows targets), and unit tests before committing (`.githooks/pre-commit` enforces this). `Cargo.lock` must match the manifests and the workspace documentation must build with rustdoc warnings denied (`.githooks/pre-push` enforces both); the refineid-core crates track core main, so refresh them with `cargo update -p refineid-rapp` when core moves. Never bypass verification with `--no-verify`. Hardware claims additionally require a real reader and card.
- Reading does not require a worktree; writing does. The main checkout is
  never edited directly. Before writing code or modifying files for any task,
  create a dedicated git worktree strictly under `../wt/`
  (`../wt/refineid-windows-<topic>`) on a `<topic>` branch. Never work
  directly on `main` or modify files in the main checkout.
- All worktrees MUST live strictly under `../wt/`, never loose beside
  repositories or in parent directories.
- Never put a git worktree under `/tmp`. It is cleared on reboot and takes the
  branch's only checkout with it.
- One task, one worktree, one branch (`<topic>`), one pull request per branch.
  Run `scripts/agent-housekeeping.sh` when starting and keep the house clean. Merge
  the pull request after mandatory local gates pass and review is complete, then
  remove the worktree and branch and fast-forward `main`. The scheduled/manual
  Windows portability workflow does not gate pull requests. Full workflow:
  `doc/process/agent-worktrees.md`.
- Clean worktrees at the start and end of every task: run
  `scripts/agent-housekeeping.sh --clean` before creating your worktree
  and again before finishing. It removes only worktrees whose branch is
  merged into main, whose tree is clean, that hold no unpushed commits,
  and that have been idle for over a day; everything else is left alone.
  If your own branch just merged and is too fresh for `--clean` to take,
  remove it yourself once its tree is clean and pushed, then delete the
  branch and fast-forward local main. If your pull request is still open
  when you finish, leave the worktree in place — a later start-clean reaps
  it after merge. Verify with `git worktree list`.
- Do not publish unsigned or test-signed binaries as production releases.

## Agent roles and authority

The front agent owns task decomposition, integration, publication, and
installation under the owner's standing authorization, including the
authorizations stated in this document, and may complete small
or tightly coupled changes itself rather than delegating. An
implementation agent owns only its assigned worktree and brief.
General instructions in this document to commit, push, open pull
requests, merge, review, file issues, or install apply to the
front agent. An explicit owner order may delegate commit on and push
to the assigned task branch for one run, with the commit and scan
rules in the brief; opening pull requests, review, issue filing,
installation, and merge are never delegated to an implementation
agent. Workers report deferred findings in their handoff for the
front agent to file. Where independence is required, the front
agent runs the review using a model from a different family than
the one that wrote the change.

## Rules live here, not in an agent's memory

Every rule, decision and finding an agent should remember lives in this
repository, never only in an agent's memory: a design rule in `doc/`, a
defect in an issue, a working rule in this file. This file states each
rule in a line and points to the reading behind it; the readings live
in `doc/`, not here.

## Product

- RefineID-Apple is the product-behavior and UX reference.
- User-facing UI is terse. Explanations, status, and diagnostics belong
  in documentation and developer tooling, not product copy.
- No confirmation dialogs: a chosen action happens.
- Only an error takes red or orange; normal states never do.
- No recovery buttons: back-offs stay silent and clear themselves.
- Details live with the reference: RefineID-Apple
  `Documentation/design/ui.md`.

## Source comments

- Comments explain what the code does now and the constraints it honors.
  Past bugs, previous implementations, and explanations of what a fix changed
  belong in commit messages, not source comments. No measurement dates
  in comments.

## Code reviews and AI reviewers

- For automated code reviews and multi-turn pull request discussions with the Muse Code agent (`muse`), always invoke with:
  ```bash
  muse --model muse-spark-1.3-contributor --reasoning-effort max
  ```
  Helper scripts `discuss-with-muse` and `review-with-muse` default to these options.
- Codex review is reserved strictly for maintainer-requested reviews (invoked only on explicit maintainer request due to expense and low quota). When requested, invoke with:
  ```bash
  codex --model gpt-6-astra -c model_reasoning_effort=high
  ```

## Commits and integration

- Commits are cheap backups. The front agent makes small, focused commits
  often, without asking for permission, once the required commit checks
  pass. Workers commit and push only under an explicit owner order in
  the brief.
- Complete the integration without waiting for another instruction
  (this instruction applies to the front agent; workers follow their
  brief): push
  the task branch, open a pull request, and merge it into `main` once mandatory
  local checks pass and review is complete. Sync local `main` with the merged
  remote.
  Use squash merges to keep the `main` history linear; do not use merge commits.

## Record deferred findings

- The front agent files a GitHub issue in the owning repository for each
  confirmed, actionable defect or quality gap that cannot reasonably be
  fixed within the current task. Filing these issues is authorized; do not
  wait for a separate instruction for each finding. An implementation
  agent reports deferred findings in its handoff instead of filing them.
- Search existing open issues first. Reuse the matching issue and add only
  new, useful evidence instead of creating a duplicate. Group findings only
  when they share a cause and can be resolved by one focused change.
- State the observed behavior, expected behavior, affected repository-relative
  paths, reproduction or inspection evidence, impact, and acceptance checks.
  Distinguish observations from hypotheses and specification requirements.
  Never claim an unexecuted test or hardware operation was verified.
- Keep speculative improvements in working notes until they have a concrete
  problem and useful acceptance criteria. Avoid issue spam and severity claims
  unsupported by evidence.
- Never put credentials, PIN data or candidate lengths, card secrets,
  personal data, private workspace paths, or persistent device identifiers
  in issue text, logs, screenshots, attachments, or reproduction fixtures.
  Report security-sensitive findings through the repository's private
  reporting process; if no safe channel is available, notify the user
  without publishing sensitive details.
- An issue does not excuse a broken gate or incomplete work needed to make
  the current task correct. Fix findings required for the task before handing
  it over; file independently deferred work with a clear scope.
- Link newly filed or reused issues in the task handoff. If issue creation is
  unavailable, preserve a sanitized finding locally and report that it was
  not filed; never silently discard it.

## Types and numbers

Two rules from refineid-core bind this repository too: refinement types
and no magic numbers. Define everything.

Refinement types:

- Read
  [refinement-types.md](https://github.com/refineid/refineid-core/blob/main/doc/architecture/refinement-types.md)
  and its case study before designing or reviewing a type.
- A type is a predicate: input from the wire, the card, the platform or
  storage crosses one border, with one constructor that checks every
  specification predicate once, and downstream code trusts the result.
- Every byte is meaning, transit or citation. Nothing raw sits beside a
  typed value, and no byte-like parameter stands where a nominal type
  belongs.
- The policy's review questions are the checklist for writing and review.

No magic numbers:

- No anonymous numeric literal in production code or ordinary tests. Every
  protocol code, status word, tag, size, offset, limit, timeout and count
  is a named constant or derives from one. Writing a hexadecimal value in
  decimal does not name its meaning.
- No hand-typed hexadecimal arrays, not even in tests. A wire buffer or an
  expected fixture is assembled from the same named constants the
  serializer uses; a synthetic test payload is an ASCII string.
- A raw wire value lives only in the initializer of a truthful named
  constant, or in one named constant holding an opaque, externally
  specified block, such as a known-answer vector, a registered identifier
  or an object identifier, with a citation to its source.

## STPA in design

Every design includes a short System-Theoretic Process Analysis (STPA),
sized to the change. [stpa-rapp.md](https://github.com/refineid/refineid-core/blob/main/doc/security/stpa-rapp.md) is the worked example and the
record for RAPP and its applications.

- Ground the analysis in the losses (L-n) and hazards (H-n) the record
  already names. Add a loss only when a real stakeholder could suffer it
  and no recorded loss covers it, and a hazard only for a real system
  state that leads to a loss.
- Do not invent imaginary losses, hazards or threats to fill the method.
  A few real ones beat a long list.
- Describe the control structure the change touches: the controllers,
  their control actions, and the feedback each gets. Look first for
  missing, late or misleading feedback; a controller acting on a stale
  process model is the usual cause of an unsafe control action.
- List the unsafe control actions (UCA-n) the affected controllers could
  issue or fail to issue, the hazards each leads to, and the controller
  constraints (CC-n) the design enforces against them.
- A small change records its analysis in the pull request, and a change
  with no control action or feedback to analyse says so in one line. A
  change to the control structure updates the STPA record that covers it.

## No backwards compatibility

- When code, a script, a command, an API, a file format or a setting is
  replaced, remove the old one in the same change. Do not leave
  compatibility wrappers, deprecated aliases, forwarding shims, fallback
  readers or migration paths behind.
- Update every caller, hook, CI job and document to the replacement in that
  same change instead of keeping the old entry point alive for them.

## Certificates and trust

- The only certificates shipped in any RefineID software are the EU
  Official Journal's list-signing certificates in the
  document-verification code; every other anchor comes from the card
  when present or from the trusted lists at runtime. The PKCS#11
  module reads the card's root from EF.4334 and its issuing CA from
  EF.4336 and presents them, with NSS trust records, while the card
  is present (`crates/refineid-pkcs11/README.md`). No fingerprints
  are shipped either.
- The Windows Card Module serves no `msroots` file: Windows would put a
  card's CAs in the user's Root store, trusted for every purpose
  (`crates/refineid-minidriver/README.md`, "No card CA"). The agent puts
  the issuing CA of each FINEID card in a reader into `CurrentUser\CA`,
  path material that grants no trust, while the card is present; no root
  enters a store in a release build (same README, "The card's issuing CA
  in the intermediate store").
- No pinning or other trust policy is added without the owner's decision.
- Describe what the code does and cite the source; ask the owner before
  changing trust behavior.

## Independent review

- Review is tiered per the working method. Before a pull request
  merges, review its diff independently with the `agy` CLI and the
  `gemini-3.8-flash-high` model, unless the change is eligible for
  self-review.
- Run `agy` headless in its sandbox and plan mode, from an empty directory,
  with the diff pasted into the prompt and no tool use. Frame the request as
  a code review from the project's author.
- Check every finding against the code. Fix the real ones and list the
  rejected ones, with the reason, in the pull request description.

## Working method

Read [doc/process/working-method.md](doc/process/working-method.md) before starting: the roles (front agent, implementation agents), what a brief contains, the feedback loops, and which documentation is kept. The same file is in every RefineID repository.
