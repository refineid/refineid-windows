# RefineID Windows agent rules

- Source and project prose may use the ISO-8859-15 character repertoire,
  including meaningful specification symbols such as `§`; do not degrade them
  to ASCII. Store each source file in the encoding required by its toolchain
  (Rust `.rs` files must be valid UTF-8). Preserve a protocol fixture's exact
  specified byte encoding.
- No AI attribution in commits.
- Zero PIN and PIN-length logging across all environments: Never log, trace,
  display, or format PIN bytes, candidate PIN lengths (e.g. `got {len}`), or
  development PIN identifiers in log sinks, audit records, or error strings.
  Never commit test PINs or card secrets.
- Safe Rust owns protocol, parsing, and secret handling. Keep `unsafe` inside
  the Windows Card Module or PC/SC boundary.
- Every Windows ABI pointer access must validate nullability and length before
  dereferencing.
- Use named constants instead of naked protocol or status values.
- Verify claims from Microsoft, DVV, ICAO, eIDAS, or another primary source.
- Always run formatting (`cargo fmt`, `csharpier`), clippy (`-D warnings` on both host and Windows targets), and unit tests before committing (`.githooks/pre-commit` enforces this). Keep `Cargo.lock` Git dependencies synchronized with upstream (`.githooks/pre-push` enforces this). Never bypass verification with `--no-verify`. Hardware claims additionally require a real reader and card.
- One task, one worktree (`~/src/wt/refineid-windows-<topic>`) on one
  `agent/<topic>` branch, one pull request per branch. Run
  `scripts/agent-housekeeping.sh` when starting and keep the house clean. Merge
  the pull request after mandatory local gates pass and review is complete, then
  remove the worktree and branch and fast-forward `main`. The scheduled/manual
  Windows portability workflow does not gate pull requests. Full workflow:
  `docs/process/agent-worktrees.md`.
- Never put a git worktree under `/tmp` or directly in `~/src/`; all worktrees
  must live under `~/src/wt/`.
- Do not publish unsigned or test-signed binaries as production releases.

## Source comments

- Comments explain what the code does now and the constraints it honors.
  Past bugs, previous implementations, and explanations of what a fix changed
  belong in commit messages, not source comments.

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

- Commits are cheap backups. Make small, focused commits often, without
  asking for permission, once the required commit checks pass.
- Complete the integration without waiting for another instruction: push
  the task branch, open a pull request, and merge it into `main` once mandatory
  local checks pass and review is complete. Sync local `main` with the merged
  remote.
  Use squash merges to keep the `main` history linear; do not use merge commits.

## Record deferred findings

- While working, file a GitHub issue in the owning repository for each
  confirmed, actionable defect or quality gap that cannot reasonably be
  fixed within the current task. Filing these issues is authorized; do not
  wait for a separate instruction for each finding.
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

## No backwards compatibility

- When code, a script, a command, an API, a file format or a setting is
  replaced, remove the old one in the same change. Do not leave
  compatibility wrappers, deprecated aliases, forwarding shims, fallback
  readers or migration paths behind.
- Update every caller, hook, CI job and document to the replacement in that
  same change instead of keeping the old entry point alive for them.
