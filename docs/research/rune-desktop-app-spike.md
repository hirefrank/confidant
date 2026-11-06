# Rune desktop app spike (2026-11-05)

> **Spike, not a product.** This document records a one-evening spike: a
> minimal Rune desktop shell over Confidant. The spike code lives at
> `spikes/rune-desktop-app/` (throwaway, own workspace, excluded from the
> main workspace and from CI). Nothing here is a commitment to ship a
> desktop app.

**Summary**
- **Verdict: proceed with caution.** The technical path works: a Rune app
  consumes `confidant-core` directly, renders real demo-vault people
  headlessly, and a scripted pointer tap selects a row — all verified on
  this VM. The reasons for caution are not technical: Rune is two weeks
  old and pre-release with no stability promise, and a second UI is a
  real ongoing cost (see "Cost of two UIs" below). The thing that could
  justify it anyway is market, not engineering: the TUI can only ever
  serve terminal-comfortable users, while a desktop app reaches the
  executives, founders, and coaches' clients who are Confidant's natural
  users. See "Verdict" for the full reasoning.
- **What the spike built:** a Rune app that loads the people roster from
  the checked-in demo vault via `confidant-core` and renders a selectable
  list with a detail pane. Two tests pass; headless `--snap` PNGs and a
  `--tree` dump were produced and inspected.

## 0. Pins and environment

- **Date:** 2026-11-05 (evening ET).
- **Rune rev pinned:** `47cb857795c3b1dd5097c15d6161719ae738ddda`
  (`dev` tip at spike time; repo created 2026-10-22, 682 stars, 1,553
  commits, 0 releases/tags, MIT). Pin a rev: Rune itself says `dev` is
  never rewritten but there is no release to pin instead.
- **Confidant base:** `09426d40d33ac923fadcd563de8643021cc75809` (main).
- **Machine:** this VM (Debian, shared Linux VM, no GPU, no display).
  Rust 1.99.0 via `~/.cargo/bin` (`rustc`/`cargo` are not on `PATH` by
  default here). `TMPDIR=$HOME/tmp`, `CARGO_TARGET_DIR=$HOME/tmp` — `/tmp`
  is a 512M tmpfs and cargo work must not use it.
- **Scratch dirs (not committed):** Rune clone at
  `~/workspace/rune-confidant-spike/rune/`; spike outputs (PNGs, tree
  dumps) at `~/workspace/rune-confidant-spike/` (`hello.png`,
  `hello-tree.json`, `spike.png`, `spike-first.png`, `spike-tree.json`).
- **Spike code (committed in this PR):** `spikes/rune-desktop-app/`
  (`Cargo.toml`, `Cargo.lock`, `README.md`, `src/main.rs`), plus a
  one-line root `Cargo.toml` `exclude` addition and an `AGENTS.md` repo-map
  row. No other repo files change.

## 1. What the spike built

`spikes/rune-desktop-app/` is a binary crate (`confidant-rune-spike`,
version 0.0.0, `publish = false`) with its own `[workspace]`, mirroring
the `fuzz/` pattern: it is listed in the root `Cargo.toml` `exclude` and
is not a member of the main workspace, so the main gate never builds it.

- **Dependency on Rune:** a git dependency pinned to the rev above
  (`rune = { git = "https://github.com/anomalyco/rune", rev = "47cb85…" }`).
  No `rune-kit` use — the spike uses only the core view API
  (`row`/`col`/`el`/`text`, `.key`, `.on_press`, `tok::theme`).
- **Dependency on Confidant:** a path dependency on
  `crates/confidant-core` (the same crate the CLI and TUI build on).
  The app calls `load_vault` + `build_roster(&vault, Some("person"),
  &PackScope::All, true)` and reads detail fields (`title`, `company`,
  `location`) from `vault.records`. No shelling out to the CLI, no JSON
  contract involved. The TUI, by contrast, renders the CLI's `--json`
  contract (`docs/tui.md`: "a terminal UI over the same agent contract
  as the CLI"); the desktop app can skip that layer and link core
  directly, which is simpler — one fewer process hop and no subprocess
  spawning per refresh.
- **UI:** a two-pane master–detail: left list of the demo vault's four
  people, right detail pane (`name` + `title · company · location`, or
  "Select a person"). Rows are keyed `person-<id>` with `.on_press`
  selecting. A `first` scene selects row 0 for headless snapshots.
- **Vault:** `CONFIDANT_SPIKE_VAULT`, else `../../examples/demo-vault`
  — the checked-in demo vault (Dana Example, Eli Sample, Fay Demo, Gus
  Example; fake data only). Never pointed at a real vault.

Reproduce from the spike directory:

```sh
cargo test
cargo run -- --snap spike.png --tree spike-tree.json
cargo run -- --snap spike-first.png --scene first
```

Headless runs need a software Vulkan driver (see §3): on this VM,
`mesa-vulkan-drivers` was installed and the runs used
`VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json`. The
`cargo test` path needs no GPU at all.

## 2. What worked (with evidence)

- **Rune's own `hello` compiles and renders headlessly.** `cargo run
  --locked -p hello -- --snap hello.png --scene on` in the Rune clone:
  first build 7m42s; the run produced a 640×400 PNG showing "Lights on"
  with the switch on (inspected visually) and a `--tree` JSON dump with
  accessibility roles/keys/bounds. This is the baseline the spike was
  measured against.
- **The spike builds and its tests pass.** First `cargo test` in the
  spike workspace took 6m07s (includes fetching the Rune git repo and
  compiling its dependency graph; incremental rebuilds ~20s). Result: 2
  passed, 0 failed —
  `roster_loads_demo_people` (demo vault loads, Dana Example present)
  and `tapping_a_row_selects_it` (a synthetic pointer tap on the first
  row via Rune's in-process `Runtime` selects it; the tap test finished
  in 0.12–0.21s, no window, no GPU).
- **Headless `--snap` / `--tree` render real vault data.** `cargo run --
  --snap spike.png --tree spike-tree.json`: 1 frame at 60 fps, GPU init
  ~240ms, first frame ~17ms; PNG is 1800×1200 and shows all four demo
  people; `--scene first` renders Dana Example selected with the detail
  pane "Dana Example / Product designer · Example Studio · Portland"
  (inspected visually). The tree dump lists all four names plus "Select
  a person", 13–15 elements. The `Runtime` test path and the `--snap`
  path agree: selection works in both.
- **`confidant-core` as a direct dependency is straightforward.**
  `load_vault` + `build_roster` + `vault.records` gave the spike
  everything it needed in ~30 lines, with no new core API. The roster
  already carries `no_ai` per entry, so the clearance information the
  UI needs is present at the point of render (see §6).
- **Exclusion holds.** `cargo metadata --no-deps` at the repo root lists
  exactly the three main members (`confidant-core`, `confidant-cli`,
  `confidant-tui`); the spike crate is not among them. `cargo fmt
  -- --check` is clean in the spike crate, and its own `Cargo.lock`
  pins Rune at the rev above.

## 3. What didn't work / blockers (exact errors)

- **Headless `--snap` needs a GPU adapter — this VM had none.**
  First run failed with exit code 2 and no PNG:
  `no GPU adapter: No suitable graphics adapter found; noop support not
  compiled in, vulkan drivers/libraries could not be loaded, metal
  support not compiled in, dx12 support not compiled in, gl support not
  compiled in, webgpu support not compiled in`.
  Rune's README documents the fix ("GPU runs without a physical GPU need
  a software Vulkan driver"): `sudo apt-get install -y
  mesa-vulkan-drivers` + `VK_ICD_FILENAMES=.../lvp_icd.json`. On this VM
  the package had no install candidate until `apt-get update` (which took
  ~11 minutes at ~108 kB/s on a slow mirror); after install, `--snap`
  worked. Consequence: **CI would need `mesa-vulkan-drivers` installed
  and `VK_ICD_FILENAMES` set for any `--snap` check**; the `Runtime`
  test path needs neither and runs in ~0.2s. Windowed runs were not
  attempted (no display here) — that path is entirely unverified by this
  spike.
- **`AppSpec::new` takes an init function, not state.** First spike
  build failed: `expected fn pointer fn() -> State, found struct State`
  (`crates/rune/src/tooling.rs:45`). The `hello` example passes
  `State::default` — a fn pointer, not a value. Fixed by passing an
  `init_state()` fn that loads the roster. A 30-second fix once read,
  but it is the kind of pre-release API shape that has no stable docs to
  lean on — the example is the documentation.
- **First layout was wrong in a way the renderer did not flag.** The
  list pane used `.w_full()` inside a `row()`, which squeezed the detail
  pane to zero width: the first PNG showed only the four names and no
  detail pane, while the tree dump still contained the detail text. Fix:
  fixed-width list pane (300pt) + `.grow(1.0)` on the detail pane. The
  flexbox gotchas are documented in Rune's README (`.grow` is `flex: g 1
  0`, collapses without a bounded ancestor), but nothing warns you at
  runtime — you find out from the PNG. This is an argument for the
  headless snapshot workflow, not against Rune: the bug was visible in
  the first render.
- **`cargo test --locked` fails on a fresh spike workspace** (no
  `Cargo.lock` yet): `error: cannot create the lock file ... because
  --locked was passed`. Generate the lockfile once without `--locked`;
  it is committed in this PR.

## 4. The TUI as it actually is (not "working TUI vs new app")

Frank's framing correction: the TUI is built but far from actually
useful, so the comparison is against the TUI as it stands, not an
idealised one. What `crates/confidant-tui` is today (read from source,
`src/views/`, `src/app.rs`, `docs/tui.md`):

- **Views that exist:** People (master–detail roster + live `context`
  bundle, local filter, a "Needs Attention" section from `check`
  findings), Check, Context (fullscreen), Doctor, Proposals, Search
  (qmd-ranked with an exact-`find` toggle), Conflicts — plus supporting
  capture, palette, alert, confirm, diff, info, help views. ~6,600 lines
  across `app.rs` (3,836) and the views. The data the desktop app would
  show for a person already exists in the TUI's context view; the desktop
  app would re-render the same data, not new data.
- **Keyboard-only.** There is no mouse or click handling anywhere in the
  TUI source (no `MouseEvent`/click handling). Navigation is keys and a
  command palette.
- **Terminal-bound.** It renders the CLI's `--json` contract by spawning
  the CLI; it needs a terminal, a `cargo install`ed CLI, and comfort
  with a keyboard UI. It cannot be double-clicked, docked, or handed to
  someone who has never opened a terminal.

**Gaps the desktop app would actually close (TUI can't, by construction):**
mouse/pointer interaction (click, scroll, drag); reaching people who
will never open a terminal; visual richness the terminal cannot do
(images, a relationship-graph canvas, markdown rendering); native OS
integration (notifications, a global-hotkey capture window, native file
dialogs — Rune has a `native-file-dialog` feature); and agent-verifiable
UI (headless PNG + element tree — the TUI cannot be screenshot-tested).

**Gaps that are missing features in *either* UI (not a framework question):**
a relationship-graph view (exists in neither; needs new layout work in
whichever UI builds it); quick capture (the TUI already has a capture
view — the desktop advantage would be a global hotkey, not the feature
itself); search (the TUI already has the qmd search view); writes back
to the vault (log touch, notes, record edits — the same
`confidant-core` write paths serve either UI, and the TUI's
proposals/apply flows show what that work looks like); richer person
detail beyond the context bundle (new data work, not new rendering).

## 5. Gaps vs what a real app needs

| Need | Rune covers today? | Evidence / note |
|---|---|---|
| People list | Yes (spike) | Renders + selects; virtualized lists (`.virtualize` + `.growth`) exist in Rune but were **not exercised** — the demo vault has 4 people, a real vault has dozens to hundreds |
| Detail view | Yes (spike) | Name + fields; full context bundle not rendered — same data as TUI's context view, re-rendering work only |
| Search | Partially | `rune-kit` has `TextInput`/`TextField`; core has `el::text_input`. No search UI built in the spike; the qmd search itself lives in `confidant-core`/CLI and would need a desktop front end |
| Text input / forms | Yes, in kit | `TextInput`/`TextField` exist; not exercised — form behaviour (focus, validation, multiline notes) is unproven here |
| Writes back to the vault | Not attempted | Would go through `confidant-core` write paths (same as the TUI's apply flows); no write was attempted in the spike |
| Graph / network view | Not attempted | Rune has vector shapes + canvas + drag; no graph built — the biggest unproven piece of the desktop pitch |
| Native packaging (.app, signing, updates) | Not attempted | Nothing in the spike; distribution is a separate workstream from rendering |
| macOS / Windows | Not attempted | Linux-only spike; Rune targets macOS/Windows/web, but none of those paths were run here |
| Accessibility | Present, untested | `--tree` dumps accessibility roles/keys/bounds; VoiceOver behaviour not tested |

## 6. Privacy

Local-only, no server: the spike reads a vault directory on disk and
renders it; Rune makes no network requests of its own. The privacy
boundary does not change — encrypted disk + private remote + `no-ai`
still applies. One distinction the spike makes explicit in code: it
loads the roster with `for_operator = true` (the operator's own app
sees every record, exactly like the TUI). **An agent-driven headless
render is a different audience**: a PNG or element-tree dump produced
for an agent is agent-facing output, so it must use the cleared roster
(`for_operator = false`), which omits `no-ai` records — the same rule
as `find`/`context`. Any future desktop work that renders for an agent
(headless checks in CI, agent-driven screenshots) needs a test proving
`no-ai` content is excluded from the PNG/tree, per hard rule 3. The
spike's `--snap` outputs in the scratch dir contain only fake demo
people, so nothing sensitive was produced here.

## 7. Licensing

Rune is MIT; Confidant is Apache-2.0. Depending on an MIT crate from an
Apache-2.0 project is compatible (MIT is permissive; no copyleft). No
license text needs vendoring for a dependency. Two cautions, both about
age rather than law: Rune has no releases, so the pin is a git rev, not
a version; and Rune's own dependency tree is large (wgpu, winit, parley,
taffy, …) — the spike's `Cargo.lock` is 113 KB and the first build took
~6 minutes, which is the cost of the dependency graph, not of Rune
itself.

## 8. Cost of two UIs

Frank's doubt, stated plainly: maintaining both the TUI and a desktop
app is a real cost, and this section is an honest attempt to price it
from what the spike actually showed. **No hour estimates here** — the
spike was one evening and cannot support them; where a number would be
invented, this says so instead.

- **Duplicated views.** Every screen exists twice: the TUI's views are
  ~6,600 lines across `app.rs` and `src/views/`; a desktop port
  re-implements each view's rendering and interaction. What is *not*
  duplicated is data loading — both UIs can share `confidant-core`
  (the spike proves the desktop side of that) — but rendering,
  layout, focus, and input handling are per-UI work, and the TUI's
  views are the ones that exist today, so the desktop starts behind.
- **Every feature twice, or divergent.** Each new capability (a new
  view, a new write flow, a search mode) needs a decision: build it in
  both UIs, or let the UIs diverge deliberately. Divergence is cheaper
  but means the two UIs stop being the same product; parity is the
  expensive option and there is no evidence in the spike about which
  the project would choose, because the spike built one view.
- **Rune's pre-release churn as a dependency.** Rune is two weeks old,
  zero releases, `dev` branch, no semver. The spike hit one API-shape
  surprise in an evening (`AppSpec::new` takes an init fn). Pinning a
  rev bounds the risk, but every bump is a potential break, and there is
  no upstream stability promise to plan against. This cost is
  front-loaded and unknowable in size until the first bump is attempted.
- **Testing burden, including headless checks.** The cheap part is real:
  `Runtime` tests run in ~0.2s with no GPU. The expensive part is the
  `--snap` path: CI would need `mesa-vulkan-drivers` + `VK_ICD_FILENAMES`
  for PNG goldens, and macOS/Windows rendering would need runners that
  exercise those backends (the spike ran Linux only). Headless checks
  also only cover what the script asserts — the spike's own layout bug
  (§3) was caught by looking at the PNG, not by any test.
- **Distribution is a second project.** Rendering is proven; shipping a
  `.app`/`.dmg` with signing, notarization, and updates is not in this
  spike at all and is not small.

**What would have to be true:**
- *Second UI worth it:* the desktop is explicitly the UI for
  non-terminal users, the TUI is explicitly the operator/dev UI with a
  defined, smaller scope (no parity chase), and there is a real cohort
  waiting for it — the test is whether anyone who cannot use the TUI
  adopts the desktop, not whether the desktop looks good.
- *Replacing the TUI:* the desktop covers every TUI view Frank actually
  uses *and* the terminal/SSH use case is explicitly abandoned. The
  spike gives no evidence for this — the TUI is the only UI that works
  over SSH today, and replacing it removes that.
- *Not building it:* no non-terminal cohort materializes, or Rune
  stalls / breaks API repeatedly on bumps, or the TUI reaches "useful"
  on its own and the desktop's marginal reach is not worth the second
  codebase. Any of these is a legitimate outcome of this spike.

## 9. Verdict

**Proceed with caution — and decide the TUI's fate first.**

The spike answers its technical question yes: a Rune app can be
Confidant's third UI consumer, sharing `confidant-core` with the CLI
and TUI, with agent-verifiable rendering that the TUI cannot offer. The
single biggest reason for caution is Rune itself: two weeks old,
pre-release, no stability promise, and the first dependency bump is
entirely untested.

But the "two UIs" question is not just maintenance cost, and the
verdict has to weigh what the second UI buys. A TUI caps who Confidant
can be marketed to — terminal-comfortable users only — while a desktop
app reaches the non-terminal audience (executives, founders, coaches'
clients) who are Confidant's natural users. That market is one the TUI
can never reach, whatever features it gains. So the desktop app is best
understood not as "a second UI for the same users" but as the UI for
users the TUI can't serve, sharing `confidant-core` underneath. If that
audience is the product's future, the maintenance cost is the price of
reaching it; if it isn't, the cost buys nothing and the spike should
stay a spike.

**Recommended next step, if proceeding:** do not start with a full port.
Build one vertical slice as the next spike — people list + search + log
touch, the three interactions that define daily use — against a pinned
Rune rev, with a headless PNG golden in CI (which needs the lavapipe
setup from §3). In parallel, decide explicitly: is the TUI the
operator/dev UI going forward, or is it on a path to replacement? That
decision, not any technical result, is what determines whether two UIs
is a cost worth paying. Revisit after Rune's first release, when the
churn question has its first real data point.

## 10. Evidence log (commands and results)

All commands run on this VM, 2026-11-05, `PATH=$HOME/.cargo/bin:$PATH`,
`TMPDIR=$HOME/tmp`.

| Step | Command / result |
|---|---|
| Rune clone | `git clone --depth 1 --branch dev https://github.com/anomalyco/rune.git` → rev `47cb857795c3b1dd5097c15d6161719ae738ddda` |
| Confidant base | `git clone --depth 1 --branch main https://github.com/hirefrank/confidant.git` → `09426d40d33ac923fadcd563de8643021cc75809` |
| Rune `hello` build | `cargo run --locked -p hello -- --snap hello.png --scene on` — compiled in 7m42s; run failed, exit 2, `no GPU adapter: … vulkan drivers/libraries could not be loaded …` (see §3) |
| Rune `hello` test | `cargo test --locked -p hello` — 1 passed in 0.09s, no GPU needed |
| lavapipe install | `apt-get update` (~11 min, ~108 kB/s) then `apt-get install -y mesa-vulkan-drivers` — `lvp_icd.json` present afterwards |
| Rune `hello` headless | `VK_ICD_FILENAMES=…/lvp_icd.json ./hello --snap hello.png --scene on --tree hello-tree.json` — 1.5s, PNG 640×400 (visually verified), tree 2,657 bytes |
| Spike first build | `cargo test` (spike workspace) — 6m07s, then 1 compile error (`AppSpec::new` init fn, §3); fixed, rebuilt in ~20s |
| Spike tests | `cargo test` — 2 passed, 0 failed, ~0.2s |
| Spike headless | `cargo run -- --snap spike.png --tree spike-tree.json` — PNG 1800×1200, 55 instances, first frame ~17ms; `--scene first` — 91 instances, detail pane rendered; `cargo test` re-run after `cargo fmt` — 2 passed |
| Exclusion check | `cargo metadata --no-deps` at repo root — members are exactly `confidant-core`, `confidant-cli`, `confidant-tui` |
| Not attempted | Windowed run (no display); macOS/Windows builds; any write back to a vault; graph view; packaging/signing |
