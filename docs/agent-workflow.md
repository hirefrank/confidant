# Agent workflow: finding and claiming work

How agents (Marigold, Firstmate, Silas) find work in this repo, claim it so nobody duplicates it, and hand it back when done. Frank is the launch authority; this doc is process, not code.

## Finding work

- A weekday-morning sweep (a scheduled Marigold job) reads all open issues and open PRs and delivers a short brief when something is actionable: newly ready issues, newly unblocked issues, stalled or failing PRs. It surfaces work only — it never starts building, comments, labels, or opens PRs.
- Launch authority is Frank's alone: he picks from the brief (or assigns work directly), then an agent builds. A reviewer's greenlight is technical direction inside an authorized run, never a launch order.

## Claiming work (before writing any code)

1. **Check** the issue first: assignee, `in-progress` label, linked PRs, and recent comments (last ~7 days) for a "starting work" note.
2. **If clear, claim it:** assign to `hirefrank` (best-effort — the token may not permit assignees), add the `in-progress` label, and post a comment: "Starting work on this — branch `<branch>`."
3. **Open a draft PR early**, linked from its body ("Fixes #N" or "Part of #N").
4. **On merge:** close the issue and remove the `in-progress` label (housekeeping: if the work is done it should be closed).
5. **If you stop without finishing:** comment what state the work is in and remove the label and assignee, so someone else can pick it up.

## Who follows this

Marigold, Firstmate, Silas, and Frank. When Frank takes an issue himself, he claims it the same way or tells Marigold to mark it.

## Caveats

- Labels and assignees are advisory, not locks — always read recent comments too.
- Never merge on anyone's behalf. Silas merges after explicit written sign-off on the head plus green CI on that head; spec-change PRs need Frank's explicit OK.
- Commit authorship is Frank's, never Marigold's; comments carry no "Marigold:" prefix.
