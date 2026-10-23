# Working method

How work moves from an idea to a merged, installed change in the RefineID
repositories. The same text is in every RefineID repository; a change to it
is made in all of them together.

Write and read this file for every skill level: a person new to the
project, a small model and a strong model must all be able to follow it.
Use plain words, give exact commands, and assume no history. This file
names the steps; this repository's AGENTS.md gives the exact commands for
its gates, tests, review and install.

## Feedback drives the work

Every step below exists to give feedback early. A controller that acts on
a stale picture of the system makes unsafe decisions; the same holds for a
developer or an agent. The loops are:

- **The owner tries the change on real devices** and says what is wrong.
- **Development builds show every error** on screen and in the system log
  (this repository's AGENTS.md). Release builds log nothing.
- **Gates** run at commit and push: format, lint, build, tests. Never skip
  them.
- **An independent review** reads every diff before it merges: a model
  from a different family than the one that wrote the change, run as this
  repository's AGENTS.md describes.
- **STPA** (System-Theoretic Process Analysis) names the feedback each
  controller needs. The record is
  <https://github.com/refineid/refineid-core/blob/main/doc/security/stpa-rapp.md>.

A finding from any loop is either fixed in the current change or filed as
an issue, with the evidence, in the repository whose code it concerns.

Disagreement is feedback too. When a request conflicts with a
specification, the front agent says so to the owner and gives an honest
view of which is better before any brief is written. Good design leads:
if the design wins, the brief includes the specification change, and the
specification change merges first.

## Roles

- **The owner** decides what the product should be and tests it.
- **The front agent** talks with the owner. It turns a request, however
  tentative, into a settled brief, hands the brief to an implementation
  agent, checks what comes back, and integrates it. A person can be the
  front agent.
- **An implementation agent** does one brief in one worktree and reports.

### A brief contains

1. The owner's words, quoted.
2. The goal in one or two sentences.
3. The authority: specification sections, STPA identifiers, design
   documents, issue numbers.
4. Constraints: rules from AGENTS.md that matter here, and what not to
   touch.
5. Where to work: repository, worktree path, branch, base commit.
6. How to verify: the exact gate and test commands.
7. What to report: files changed, decisions made, results with commands,
   open questions, a suggested commit message.

### An implementation agent

- Works only in its own worktree. From the repository's main checkout:

  ```sh
  git fetch origin
  git worktree add ../wt/<repository>-<topic> -b <topic> origin/main
  ```

  `../wt/` is the `wt` directory beside the main checkout; worktrees live
  nowhere else.
- Runs the gate and test commands from AGENTS.md by hand in the worktree.
- Does not commit, push, open pull requests, merge or install. It leaves
  the change uncommitted and reports.
- Reports decisions and ambiguities instead of guessing; the front agent
  takes the ones that are the owner's to the owner.
- Reports what it ran and what the result was, word for word. "Not run" is
  a valid result; a claimed result that was not run is not.

### The front agent

- Checks the result against the code, not against the report.
- Scans the diff, and every text it publishes, for personal data (see
  below) and secrets.
- Runs the independent review, fixes or rejects each finding, and lists
  the rejected ones with the reason in the pull request.
- Commits, pushes through the gates, opens the pull request, merges it, and
  installs the merged main on the owner's devices.
- Gives two changes that edit the same files to agents one after the
  other: the second starts from main after the first has merged.
- Tells the owner what changed and what to test, briefly.

## Personal data

These repositories are public. Nothing that is kept may hold personal
data: no person's name, identity code, certificate content, card, device
or reader serial number, PIN or card access number, host or device name,
network address, or the date of a person's test. That covers code, tests,
commits, issues, pull requests, news entries and any log pasted into them.
Tests use synthetic identities. Redact a log before it is quoted.

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
