# Touch vs interaction: where the line is (#749)

Confidant has two contact-ish shapes: a **touch** (a ledger line: date,
kind, optional duration and 1:1/group mode) and an **interaction** (a
record: date, title, body, participants). Nothing in the file format says
which source material becomes which, so enrichment historically funnelled
everything into touches by default. That was a choice made by accident.

This is the decision, the examples it was made from, and the mechanism that
makes it visible in `context`.

## The line

**A contact earns an interaction when there is a body worth reading later.
Without a body it is a touch.**

- A touch answers *when, how, how long, and one-to-one or group*. It is
  contact memory, not minutes of a meeting. It belongs in the ledger.
- An interaction answers *what happened and what was said*. It is a record
  with a title and a body, so it can be read, linked, and corrected like any
  other record.
- The two are not alternatives to write by hand: adding an interaction
  mirrors a minimal `touch` line for its primary person and each
  `with:` participant (`record add`, spec §6). So "both" is not a third
  choice; it is "interaction, which counts as contact automatically."
  **Never hand-log a touch for an interaction.** That double-counts contact
  and splits the same moment across two stores.

Facts that are not contact at all — role, relationship context, preferences,
a one-off piece of context — go in profile fields or a note. A note is not
contact either: it has no touch and never moves a cadence.

## Worked examples

| Source material | Shape | Why |
|---|---|---|
| 1:1 coaching session | **Touch** (`meet`/`video`, `duration:60m`, `mode:one-on-one`) | Contact with a known shape and no body. Settled by usage. If the session produced notes or decisions, log an interaction instead; the mirrored touch keeps the contact count. |
| Substantive 1:1 email thread | **Touch** (`email`, `mode:one-on-one`) when it is just a thread of contact; **interaction** when the thread carries decisions, commitments, or context worth rereading | The deciding question is the body, not the medium. A thread with substance is an interaction (and mirrors the touch); a short "good to reconnect" thread is a touch. Do not log both by hand. |
| Bulk investor update | **Note** | One-to-many broadcast, not an exchange. It may be dated and linked to the person, but no contact happened. Settled. |
| Group social (game night, reunion) | **Touch** (`event`/`meal`, `mode:group`, `duration:` if known) when it is still contact with the person and there is no body; **interaction** when the event has a body or several participants whose shared record matters | `mode:group` is the mechanism: it says this was a gathering, so the days-since-touch read does not treat it as a 1:1. A group interaction mirrors a kind-less touch for every participant. |
| Meeting with an agenda, minutes, or decisions | **Interaction** | The body is the point. Mirrors touches for everyone on it. |
| Intro email that connects two people | **Touch** (`email`) for the person contacted | The fact is the contact; there is no body to keep. |
| Conference badge scan, cold outreach | **Nothing** | Not a relationship; do not mint a record or a touch (see the capture policy in `SKILL.md`). |
| "She was my boss at Acme, then founded Liftoff" | **Profile** (`role_history`, `relationship_context`) | A fact about the person, not a moment of contact. |

The grey zone is deliberate and small: **substance decides, not medium**. A
phone call with a decision in it is an interaction; a long email that only
says hello is a touch.

## The mechanism, not just prose

The boundary uses the `personal@0.4` richness pairs instead of a new field:

- `mode:one-on-one|group` is what makes a group gathering legible as contact.
  A birthday game night is a `touch` with `mode:group`; a 1:1 coffee is the
  same kind with `mode:one-on-one`. Without it, every days-since-touch read
  treats a party as a private conversation.
- `duration:<N>m` records how long a session or call ran, so a 60-minute
  session is a fact on the line instead of prose in a note.
- An interaction has a body and participants; `record add` mirrors the
  contact line, so the ledger stays complete without a second write.

## What `context` shows

`context` returns both stores and, since #749, a merged **`timeline`** array:
interactions and touchpoints in date order (ascending; a dateless
interaction sorts last; a touch sorts before an interaction on the same
date), each entry tagged `"type": "touch" | "interaction"`. The timeline
carries exactly the fields and privacy of its source arrays — the §12
cleared set, pack scope, retirement, and the operator-only `superseded` and
`no_ai` fields apply identically — because it is built from those arrays,
not re-queried.

The timeline is a view, not a third store. `touchpoints` and `interactions`
remain the canonical arrays; a consumer that wants the split keeps using
them.

## Where the rule lives

- **Rationale and examples:** this document.
- **Operating policy (what an agent applies):** `packs/personal/SKILL.md`,
  "Touch or interaction?", extended in the capture-policy section.
- **Format:** no change. This decision adds no field and no ledger grammar.
