# Working method

How work moves from an idea to a merged, installed change in the RefineID
repositories. The same text is in the five active implementation
repositories (refineid-core, refineid-apple, refineid-android,
refineid-unix, refineid-windows); a change to it is made in all five
together.

Write and read this file for every skill level: a person new to the
project, a small model and a strong model must all be able to follow it.
Use plain words, give exact commands, and assume no history. This file
names the steps; this repository's AGENTS.md gives the exact commands for
its gates, tests, review and install.

## Assurance over ceremony

Exercise judgment to advance the task. Follow invariants without exception.
Apply process in proportion to the change's risk and uncertainty. Do not
create delegation or documentation merely to demonstrate
activity. When a simpler workflow provides sufficient assurance, use it.
Simplification applies only to default practices; it never removes
required assurance or alters authority limits.

Instructions fall into three categories:

- **Invariants**: unconditional requirements, namely the shared
  security invariants: PINs, PUKs, and the CAN never travel over any
  network, and PIN codes, PUK, CAN, PIN data, candidate lengths, and
  character offsets are never logged. Unconditional rules in AGENTS.md
  bind equally. Zero exceptions, regardless of change size.
- **Required assurance**: at minimum, the repository's gate floor selected by change scope,
  independent review where required below, STPA sized to the change
  for any change with a control structure to analyse, and hardware
  verification where AGENTS.md requires it.
- **Default practices**: useful workflows (briefs, delegation) that the
  front agent can simplify when a change is self-evident and adds no
  risk. Worktrees are not simplifiable: the main checkout is never
  edited directly. A simplified brief keeps every field of the brief
  template; simplification shortens prose, never drops fields. The
  review tier is never simplifiable.

## Feedback drives the work

Every step below exists to give feedback early. A controller that acts on
a stale picture of the system makes unsafe decisions; the same holds for a
developer or an agent. The loops are:

- **The owner tries the change on real devices** and says what is wrong.
- **Development builds show every error** on screen and in the system log
  (this repository's AGENTS.md). Release builds log nothing.
- **Gates** run at commit and push. Allowlisted prose-only changes run
  documentation checks; code, mixed changes and unknown paths run the strict
  engineering floor. Never bypass the hooks. Continuous integration reports problems after the merge; it never
  gates one.
- **Review** reads every diff before it merges: trivial changes may be
  self-reviewed; consequential diffs need independent review by a model
  from a different family than the one that wrote the change, run as
  this repository's AGENTS.md describes. See [Review](#review) below.
- **STPA** (System-Theoretic Process Analysis) names the feedback each
  controller needs. The method and its literature:
  <https://github.com/refineid/refineid-core/blob/main/doc/stpa.md>. The
  record: <https://github.com/refineid/refineid-core/blob/main/doc/security/stpa-rapp.md>.

A finding from any loop is either fixed in the current change or filed as
an issue, with the evidence, in the repository whose code it concerns.
A known defect is not parked as a future issue: the issue records it
and the fix is queued behind the current change, each in its own branch.

Disagreement is feedback too. When a request conflicts with a
specification, the front agent says so to the owner and gives an honest
view of which is better before any brief is written. Good design leads:
if the design wins, the brief includes the specification change, and the
specification change merges first. Usable beats strict: when strict
wording would break real use, the brief proposes the practical behavior
with a bounded rule. Never add privacy theatre: no extra padding or
fixed sizes against observers of encrypted traffic beyond what the
protocol requires.

## Roles

- **The owner** decides what the product should be and tests it.
- **The front agent** talks with the owner. It turns a request, however
  tentative, into a settled brief, hands the brief to an implementation
  agent, checks what comes back, and integrates it. A person can be the
  front agent.
- **An implementation agent** does one brief at a time in one worktree
  and reports.

### When to delegate

Delegate when the task has no open interpretation, a bounded change
surface, and an independently checkable result. The front agent retains
unresolved
specification interpretation, security policy, cross-repository design,
and acceptance decisions. Small or tightly coupled changes may be
completed by the front agent itself rather than delegating.

Assign implementation agents by demonstrated capability on the
task class, not permanent model rankings. Every assignee follows
the implementation agent rules.

- **Scouting agent**: inventory callers, check references, report
  paths and evidence.
- **Coding agent**: implement an approved change and its specified
  failure cases (for example, an adapter).
- **Design agent**: draft changes to credential custody, retry behavior,
  trust, or protocol state for front-agent decision.

### A brief contains

1. The owner's words, quoted.
2. The goal in one or two sentences.
3. The authority: specification sections, STPA identifiers, design
   documents, issue numbers, and any owner order delegating commit
   and push, with its commit and scan rules.
4. Constraints: rules from AGENTS.md that matter here, what not to touch,
   and allowed changes (files, interfaces, and the brief's
   repository).
5. Decisions already settled: invariants and behavior the worker must
   preserve.
6. Where to work: repository, worktree path, branch, base commit.
7. How to verify: the exact gate and test commands.
8. Acceptance: observable success and failure behavior.
9. Stop and report when: contract changes, conflicting evidence, scope
   expansion, two failed attempts at the same problem without new
   evidence (an attempt is one edit-and-verify cycle; new evidence is
   a new fact changing the diagnosis, not a different symptom of the
   same cause), or four failed attempts at the same problem in total.
10. Evidence required: base revision, commands, exit status,
    untested items.
11. What to report: files changed, decisions made, results with commands,
    open questions, a suggested commit message, and deferred findings for
    the front agent to file.

### An implementation agent

- Works only in its own worktree. From the repository's main checkout:

  ```sh
  git fetch origin
  git worktree add ../wt/<repository>-<topic> -b <topic> origin/main
  ```

  `../wt/` is the `wt` directory beside the main checkout; worktrees live
  nowhere else.
- Runs the gate and test commands from AGENTS.md by hand in the worktree.
- An AI implementation agent runs sandboxed.
- Does not commit, push, open pull requests, merge, review, file
  issues, or install. It leaves the change uncommitted and reports
  findings in its handoff for the front agent to file. An explicit
  owner order may grant
  commit and push rights for one run only, with the commit and scan
  rules in the brief; opening pull requests, review, issue filing,
  installation, and the merge stay with the front agent.
- Resolves local implementation choices itself when they preserve all
  invariants, security policy, and settled decisions. Escalates
  anything touching security policy, anything ambiguous, and anything
  that changes the brief's contract.
- After two unsuccessful attempts at the same problem without new
  evidence, or four unsuccessful attempts at the same problem in
  total, stop work and report the smallest reproduction, what was
  tried, what uncommitted changes remain, and the unresolved
  question. Never weaken a check or test to complete the brief.
- Reports decisions and ambiguities instead of guessing; the front agent
  takes the ones that are the owner's to the owner.
- Reports what it ran and what the result was, word for word. "Not run" is
  a valid result; a claimed result that was not run is not.

### The front agent

- Treats a worker's report as a guide to inspection, not proof. Inspects
  the actual diff, checks scope and invariants, and verifies the required
  evidence against the final code, not the report. Re-runs checks when the
  evidence is missing, stale, or affected by subsequent edits. Hardware
  acceptance remains required where AGENTS.md requires it.
- Files deferred findings reported in worker handoffs: searches
  existing issues first, then files each confirmed defect or quality
  gap in the owning repository.
- Verifies commits and pushes directly in its own session using git
  log and status, never from an agent's report. If the owner drives an
  agent directly, it stands down rather than fight for the machine.
- Scans the diff, and every text it publishes, for personal data (see
  below) and secrets.
- Runs independent review, except for self-reviewed trivial changes;
  fixes or rejects each finding, and lists the rejected ones with the
  reason in the pull request.
- A hardware acceptance item (a real card must complete something)
  blocks the merge: the front agent asks the owner to run it and
  proceeds to merge only after it passes. Merging first and filing a
  follow-up issue instead is not allowed.
- Commits, pushes through the gates, opens the pull request, merges it
  by squash without rebasing onto main first, and installs the merged
  main on the owner's devices when the change affects a shipped
  application (its code, build, dependencies, or behavior); when in
  doubt, install. The squash carries a body
  composed from the branch's commits, passed explicitly, so no footer
  reaches history, with the sole exception of the required
  `Self-reviewed:` marker for self-reviewed trivial changes.
- Removes the worktree and deletes the branch only after the merge is
  confirmed, each in its own step. Destructive commands are never
  chained after other commands. Signing secrets are never copied or
  removed by agents.
- Gives two changes that edit the same files to agents one after the
  other: the second starts from main after the first has merged.
- Asks the owner one question at a time, the most impactful first, and
  carries on with unblocked work between answers.
- Says in chat, before merging, what the change does beyond the brief:
  a new flag, a changed default or exit code, a step on a machine. The
  pull request description does not count as telling, and a step beyond
  the brief waits for the owner's word.
- Presents the comparative review and the design before a dramatic
  change (a big port, a merge of implementations, a deletion of a
  stack) and starts only on approval.
- Adds no user-visible state, message, outcome or option without asking
  first; a new case reuses an existing outcome or error instead of
  inventing one.
- Tells the owner what changed and what to test, briefly, naming
  specification identifiers (MF, EF.CardAccess), not bare hex.

## Review

Review is tiered: every change is reviewed before merge. Trivial changes
may be self-reviewed as described below; every other change needs
independent review, run as this repository's AGENTS.md describes.

- Self-review for trivial changes: the front agent self-reviews a
  trivial change whose complete effect is readily apparent from the
  diff and that changes none of the following: executable behavior,
  security policy, protocol meaning, dependencies, build or release
  behavior, or instructions governing agent authority.
  - Eligible cases (exhaustive): comment prose corrections
    (excluding doctests, doc attributes, code blocks, and tool
    directives such as lint suppressions or formatter controls,
    which can execute or change tool behavior), output of the
    repository's own formatter and nothing else, broken
    documentation links with an unambiguous replacement, and minor
    wording in documentation prose that preserves meaning, touches
    no sentence stating a requirement, constraint, or invariant
    (such as sentences carrying MUST, SHALL, SHOULD, REQUIRED,
    always, never, do not, cannot, prohibited, or not allowed, in
    any letter case), and changes no program text such as UI
    strings, log formats, error messages, or test-asserted text.
  - Run the repository's scope-selected gate floor; another agent's review is not
    required. For delegated trivial work, the front agent's inspection
    completes the review; do not recruit a third agent. Only the front
    agent may self-review.
  - Record the matching markers as lines in the squash body, one per
    category touched: `Self-reviewed: wording only; meaning
    unchanged`, `Self-reviewed: formatting only`, or `Self-reviewed:
    link fix only`. Comment prose corrections take the wording
    marker. No separate justification document or owner approval is
    needed.
- Consequential changes: every change not eligible for self-review
  requires independent review. In particular, semantic changes to
  credential custody, trust decisions, cryptography, protocol state,
  or card retry behavior always require independent review.
- Semantic effect over line count: judge by semantic effect, not line
  count or file extension. Any logic, signature, or control-flow change
  requires independent review, even if one line. If the effect is
  uncertain, investigate or obtain review. Do not split a consequential
  change into small patches to evade review.
- Disagreement: if there is any disagreement or doubt about whether
  a change is trivial, treat it as consequential.

## Personal data

These repositories are public. Nothing that is kept may hold personal
data: no person's name, identity code, certificate content, card, device
or reader serial number, PIN or card access number, host or device name,
network address, or the date of a person's test. That covers code, tests,
commits, issues, pull requests, news entries and any log pasted into them.
Tests use synthetic identities. Redact a log before it is quoted.
Public text never names another vendor's middleware or a private
repository; findings are stated in neutral terms.

## What is kept and what is not

Kept:

- **Specifications** state the protocol as it is at its stamped version.
- **Design documents** describe the product as it is now: screens,
  behaviour, rules. They carry no history.
- **The STPA record** in refineid-core.
- **A news track**: `news.md` in this repository's documentation
  directory. One line per change, newest first, in the form
  `YYYY-MM-DD What changed, in one sentence. [Where](link)`, the link
  pointing to the design document, specification or pull request that
  holds the substance. It is an index, not a diary.
- **Pull request descriptions** say what changed, why, how it was tested,
  and what the review found.
- **Issues** hold confirmed defects and gaps that are not fixed yet.

Not kept: chat, briefs, agent transcripts and other working material. What
matters from them is written into the documents above before the work
ends.

## Illustrative example: platform adapter delegation and escalation

(The paths, symbols, and events below are illustrative; they show
delegation boundaries and escalation mechanics across languages.)

1. Context: a platform adapter needs an updated card status notification.
2. Decomposition (front agent):
   - Verifies the protocol interface is settled in the design documents.
   - Issues a brief to an implementation agent:
     - Allowed changes: `adapter/monitor.*`, `tests/adapter_tests.*`.
     - Decisions settled: preserve retry intervals; reuse the existing
       status enum.
     - Stop and report when: handling the event requires modifying core
       protocol types or core repositories.
     - Acceptance: the event updates local status; disconnect resets
       state; tests pass.
3. Execution and escalation (implementation agent):
   - The worker implements the adapter logic in `adapter/monitor.*`.
   - The worker finds that the core status event type lacks an error
     variant needed for this case.
   - Escalation: instead of inventing an unapproved variant or editing
     core repositories, the worker halts per the brief's stop condition:
     "Stopped: handling this status requires adding a variant to
     `CardError` in core. Uncommitted work remains: partial adapter
     logic and the reproduction test in `tests/adapter_tests.*`."
4. Resolution (front agent):
   - The front agent verifies the reproduction, designs the core
     change, runs it through the required gates and independent
     review, including a second reviewer for this protocol change,
     then merges it in the core repository and issues an updated
     brief naming the new base commit.
