---
name: "report-a-problem"
description: "Draft and file a well-formed Confidant issue from the conversation: collect structural diagnostics (version, host shape, doctor check lines), search open issues for a duplicate before creating one, and post only after the operator confirms the exact title, body, destination, and labels. Never includes vault contents; falls back to a ready-to-paste draft and new-issue link when filing is not possible."
---

# Report a problem

Use this skill when the operator hits a bug, a rough edge, or confusing
behaviour in Confidant, or says "file a bug", "report this", or "this is
broken". The operator describes what happened; you collect the context,
redact it, search for a duplicate, and file only after an explicit
confirmation.

This must work mid-setup, when the operator may be non-technical and the
install may be half-finished: the CLI can be missing, the vault absent, the
network offline. Never ask the operator to gather versions or run
diagnostics.

## 1. Draft from the conversation

Before running anything, write down:

- **What happened** — the observed behaviour, in the operator's words where
  possible.
- **What was expected** — what they thought would happen.
- **Steps** — the shortest sequence that shows it, starting from a known
  state ("after `confidant setup`", "when running `confidant find x`"). If
  the steps cannot be reconstructed, say what is known and mark the gap;
  never invent them.
- **Impact** — once or every time; blocks setup or cosmetic.

Rules:

- **One issue per problem.** If the conversation contains two, ask which to
  file first.
- **Use their words, not their data.** Replace a person, org, note, or
  transaction with "a record" or "a record I had just created". No names,
  bodies, ledger lines, contact details, IDs, or paths from the vault.
- **Do not paste a terminal transcript.** Quote only the failing command
  (flags included) and the error line, redacted.
- **Keep the error code** if there is one (`E_…`): codes are stable,
  messages are not.
- **Keep the reproducer safe:** no real data, no secrets, no absolute vault
  paths.

## 2. Collect structural diagnostics

Run what is available; never fabricate a version or output you could not
run.

```sh
confidant --version            # if missing: say "not installed / not on PATH"
uname -srm                     # Linux, macOS, or WSL2 host shape
# macOS, optional: sw_vers -productVersion
confidant doctor --json --no-input
```

From `doctor --json`, keep per check: `id`, `status`, and a redacted
one-line `message`. Summarize the counts (`ok`, `warning`, `error`,
`unknown`) and keep the check lines that carry signal. If `doctor` cannot
run — no vault, no CLI, an error — say that: the inability to run it is
itself diagnostic.

Optional, only if cheap and structural: the TUI version when installed, and
whether `CONFIDANT_OFFLINE` is set (the fact, not other environment).

### Redaction pass (before anything is shown)

Replace or drop, and say which was done:

| Pattern | Replace with |
|---|---|
| home path, vault path, any absolute path | `~`, `<vault>`, `<path>` |
| git remote URLs and hostnames | `<remote>` |
| email addresses, phone numbers, handles | `<contact>` |
| `CONFIDANT_DEVICE_KEY`, tokens, any `CONFIDANT_*` secret value | `[redacted]` |
| long random-looking strings (40+ chars: hex, base64, ULID) | `[redacted]` |
| 12- or 24-word phrase-shaped strings | `[redacted]` |
| person, org, deal, or note names | `a person`, `an org`, `a record` |
| ledger lines, note bodies, quoted messages | drop; describe the shape instead |

Examples:

- `confidant log touch p-01M3TC5H… call` → `confidant log touch <record> call`
- `/home/…/vault/people/…` → `<vault>/people/<record>`
- `https://example.invalid/private/vault.git` → `<remote>`

Never print an environment variable wholesale. If a value might be a
secret, leave it out.

## 3. Search before filing

Unless offline (section 6), search open issues for the symptom, not for the
proposed fix.

With `gh`:

```sh
gh auth status --hostname github.com   # only proceed when this succeeds
gh issue list --repo hirefrank/confidant --state open \
  --search "<3-6 distinctive words>" --limit 20 \
  --json number,title,url,labels
```

Without `gh`, use the API and a token when one is present (`GH_TOKEN` or
`GITHUB_TOKEN`):

```sh
curl -sS -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
  "https://api.github.com/search/issues?q=repo:hirefrank/confidant+is:issue+is:open+<terms>"
```

If the search API is rate-limited, list open issues
(`GET /repos/hirefrank/confidant/issues?state=open&per_page=100`) and filter
the titles locally.

Try two or three keyword sets: the error code, the command, the visible
symptom. **Search terms are also sent over the network**, so use command,
error, and feature words — never a person, org, or note name. Read the
closest hits before deciding.

If one is clearly the same problem, offer a structured choice (meta skill
rule 2):

- **Add a comment to #N — Recommended.** New evidence or a reproduction
  belongs on the existing issue.
- **File a new issue.** A different symptom, or the existing one is about
  something else.
- **Don't file.** They only wanted the draft.

When commenting, draft the comment separately — what you saw, the new
evidence, the version — with no "+1" and no repeat of the original report.
It gets the same confirmation as a new issue.

## 4. Compose the issue

**Title:** one line, what is broken and where, no vault names. For example
"setup: `--copy` leaves skill links stale on macOS" or "find: empty result
for an exact display name that `context` resolves".

**Body:**

```markdown
### What happened

<observed behaviour, in the operator's words>

### What I expected

<what should have happened>

### Steps to reproduce

1. <from a known state>
2. <the failing command, with arguments redacted>
3. <what appears>

### Environment

- confidant: <version, or "not installed / not on PATH">
- OS: <Linux 6.11 x86_64 | macOS 15.1 arm64 | WSL2>
- Install: <release binary | cargo | unknown — infer from its path, never guess>
- Doctor: <n> ok, <n> warning, <n> error, <n> unknown
  - `<status>` `<id>`: <redacted message>
  - `<status>` `<id>`: <redacted message>

### Notes

Diagnostics are structural only: versions, host shape, and `doctor` check
lines. No vault contents are included: no record names, notes, or ledger
lines.
```

Choose at most one existing label: `bug` for a defect, `enhancement` for a
missing capability or rough edge. If unsure, leave labels off rather than
invent one.

## 5. Confirm, then post

Show the operator the **exact title, body, destination, and labels**, then
ask with a structured choice:

- **Post it — Recommended.** The draft is accurate and goes to
  `hirefrank/confidant`.
- **Edit it first.** They want wording changed.
- **Save a local draft.** Nothing is posted.
- **Don't file.** Stop.

The destination is `hirefrank/confidant` (the upstream repository) by
default. If the operator installed from a fork or asks for somewhere else,
confirm the destination before posting.

Post only after an explicit yes to that exact text. A request to see the
draft, silence, or a yes to an earlier step is not approval.

With `gh`:

```sh
gh issue create --repo hirefrank/confidant \
  --title "<confirmed title>" --body-file <private-temp-file>
# add --label bug or --label enhancement only when the draft already has one
```

Write the body to a private temp file outside the vault (`mktemp`, 0600),
and delete it afterwards. To comment instead:

```sh
gh issue comment <N> --repo hirefrank/confidant --body-file <private-temp-file>
```

Without `gh` authentication, POST the same fields to the API with the token:

```sh
curl -sS -X POST \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/hirefrank/confidant/issues \
  -d @<private-json-payload>

# comment: POST /repos/hirefrank/confidant/issues/<N>/comments
```

Report the issue URL and number, then stop. If posting fails, keep the
draft and move to the fallback; do not retry in a loop.

## 6. Fallbacks: a ready-to-paste draft

Use a fallback when `gh` is unavailable or unauthenticated and no API token
is present, when the operator declines, when the network fails, or when
`CONFIDANT_OFFLINE=1` is set.

- **Offline means offline.** Make no network calls at all — including the
  duplicate search — and say that the search was skipped.
- Produce a ready-to-paste title and body in one markdown block, plus a
  prefilled new-issue link:
  `https://github.com/hirefrank/confidant/issues/new?title=<encoded>&body=<encoded>`.
  URL-encode both; if the link would be too long, give the plain
  new-issue link and the draft separately.
- Say plainly that **nothing has been posted**, and where to paste it.
- Offer to save the draft to a file outside the vault.
- Never post from a fallback without returning to section 5's
  confirmation.

## Guardrails

- **No vault contents, ever.** No record bodies, names, emails, phone
  numbers, notes, ledger lines, IDs, or paths. Diagnostics are structural:
  versions, counts, check ids and statuses, redacted messages.
- **Exact confirmation.** The operator sees the exact title, body,
  destination, and labels; propose → confirm → apply, in those words.
- **No fabrication.** If a command could not run, write "not available" and
  why. Never guess a version, a host, or a doctor result.
- **Secrets hygiene.** Run the redaction pass on every line, including
  quoted output. Never echo `CONFIDANT_DEVICE_KEY`, tokens, or
  phrase-shaped strings.
- **One issue per problem, one post per confirmation.** No retries in a
  loop, no cross-posting, no editing someone else's issue.
- **Plain English.** The operator may be mid-setup and non-technical. You
  collect the context, explain what will be posted, and keep the language
  free of internal vocabulary (meta skill rule 1).
