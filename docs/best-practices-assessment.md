# OpenSSF Best Practices badge — passing-level self-assessment

Assessment of `github.com/hirefrank/confidant` against the
[OpenSSF Best Practices (CII) passing badge criteria](https://www.bestpractices.dev/en/criteria/0),
prepared to fill in the questionnaire for [issue #237](https://github.com/hirefrank/confidant/issues/237).

- **Date:** 2026-10-14
- **Assessed commit:** `0a91fb8` (detached worktree `/tmp/opencode/issue-237`, from `origin/main`)
- **Criteria source:** https://www.bestpractices.dev/en/criteria/0 (67 passing-level questions)
- **Method:** criteria read from the site; status derived from files in this worktree and from
  `gh api repos/hirefrank/confidant` (rulesets, security settings, releases). No enrollment was
  performed — that needs Frank's GitHub login (see *Enrollment* at the end).

## Summary

| Status | Count |
|---|---|
| Met | 63 |
| N/A | 4 (each with a justification below) |
| Unmet | 0 |
| **Total** | **67** |

All four previously-flagged gaps are now closed and **Met**: branch protection
([#234](https://github.com/hirefrank/confidant/issues/234), ruleset `Protect main` is active),
fuzzing ([#235](https://github.com/hirefrank/confidant/issues/235), `fuzz/` targets exist),
Scorecard ([#236](https://github.com/hirefrank/confidant/issues/236), `scorecard.yml` + README badge),
and dependency updates (`.github/dependabot.yml`). No unmet criterion currently maps to an open issue.

Two claims are **Met but weak** and are called out in [Weakest claims](#weakest-claims-review-before-submitting);
they are the ones to double-check wording on before submitting.

## Legend

- **Level:** MUST / SHOULD / SUGGESTED, as the criteria page labels each item.
- **Status:** Met / Unmet / N/A. "Met (weak)" is still Met; it is flagged for review.
- Evidence cites the file or setting that satisfies the criterion.

---

## Basics

| # | Criterion | Level | Status | Evidence |
|---|---|---|---|---|
| 1 | `description_good` — website describes what the software does | MUST | Met | `README.md` opening paragraph + repo description ("Confidant is relationship memory you own…"). |
| 2 | `interact` — how to obtain, give feedback, contribute | MUST | Met | `README.md` `## Install` links crates.io/Releases; `CONTRIBUTING.md`; GitHub Issues. |
| 3 | `contribution` — contribution process explained | MUST | Met | `CONTRIBUTING.md` ("Setup", PR-based workflow, one PR per topic). |
| 4 | `contribution_requirements` — acceptable-contribution requirements | SHOULD | Met | `CONTRIBUTING.md` (fmt/clippy/test/deny/audit gates) and `AGENTS.md` (hard rules, spec-is-contract). |
| 5 | `floss_license` — released as FLOSS | MUST | Met | `LICENSE` = Apache-2.0; `license = "Apache-2.0"` in `Cargo.toml`; SPDX in crate manifests. |
| 6 | `floss_license_osi` — OSI-approved license | SUGGESTED | Met | Apache-2.0 is OSI-approved. |
| 7 | `license_location` — license in a standard location | MUST | Met | `/LICENSE` at repo root; also `THIRD_PARTY_LICENSES`. |
| 8 | `documentation_basics` — basic documentation | MUST | Met | `README.md` (install, quickstart, command table, packs), `docs/`, `spec/0.1.md`. |
| 9 | `documentation_interface` — reference docs for the external interface | MUST | Met | `spec/0.1.md` (file format), `README.md` command table + ADR-7 `--json`/`--no-input` contract, `spec/findings.md`. |
| 10 | `sites_https` — repo/download sites support HTTPS/TLS | MUST | Met | Repo and Releases over HTTPS (`github.com`); crates.io is HTTPS; `Cargo.toml` `homepage`/`repository` are https URLs. |
| 11 | `discussion` — searchable, URL-addressable, open discussion | MUST | Met | GitHub Issues/PRs — searchable, each URL-addressable, no proprietary client needed. |
| 12 | `english` — docs in English, accepts English reports | SHOULD | Met | All repo docs are English. |
| 13 | `maintained` — project is maintained | MUST | Met | `pushed_at` 2026-10-14; three tagged releases since 2026-10-12; 100 PRs, 26 open issues, daily CI. (Scorecard's `Maintained 0` is only its "<90 days old" heuristic — a known false signal for a new project.) |

## Change Control

| # | Criterion | Level | Status | Evidence |
|---|---|---|---|---|
| 14 | `repo_public` — public VCS repo with a URL | MUST | Met | `github.com/hirefrank/confidant`, `private: false`. |
| 15 | `repo_track` — tracks what/who/when | MUST | Met | Git history; every commit has author + date. |
| 16 | `repo_interim` — interim versions for review, not only releases | MUST | Met | 100 merged PRs; many commits between tags. |
| 17 | `repo_distributed` — common distributed VCS | SUGGESTED | Met | git. |
| 18 | `version_unique` — unique version per release | MUST | Met | Tags `v0.1.0`, `v0.1.1`, `v0.2.0`; `version = "0.2.0"` in `Cargo.toml`. |
| 19 | `version_semver` — SemVer or CalVer | SUGGESTED | Met | `CHANGELOG.md` states SemVer; pre-1.0 policy documented. |
| 20 | `version_tags` — releases identified in the VCS | SUGGESTED | Met | Git tags per release. |
| 21 | `release_notes` — human-readable release notes | MUST | Met | `CHANGELOG.md` (Keep a Changelog) + per-release GitHub Release bodies generated from the changelog (e.g. `v0.2.0`). |
| 22 | `release_notes_vulns` — every fixed known vuln listed | MUST | **N/A** | No CVE-numbered (or similar) vulnerability has ever been fixed in a release; the project is ~1 week old and no vulnerabilities have been reported. |

## Reporting

| # | Criterion | Level | Status | Evidence |
|---|---|---|---|---|
| 23 | `report_process` — a way to submit bug reports | MUST | Met | GitHub Issues enabled; `CONTRIBUTING.md`/`SECURITY.md` point at them. |
| 24 | `report_tracker` — issue tracker for individual issues | SHOULD | Met | GitHub Issues with labels (`bug`, `enhancement`, `size:*`, `blocked`, …). |
| 25 | `report_responses` — majority of bug reports acknowledged in 2–12 months | MUST | Met (weak) | Project is ~1 week old (created 2026-10-07), so the 2–12 month window is not yet reachable; every filed issue has been triaged/answered the same day. Answer honestly on the form — if the app allows it for a <2-month project, note "project younger than window"; otherwise yes. |
| 26 | `enhancement_responses` — respond to majority of enhancement requests | SHOULD | Met (weak) | Same window caveat; enhancement/`-review` issues are all answered within a day (e.g. #300, #295, #264). |
| 27 | `report_archive` — public searchable archive of reports | MUST | Met | `github.com/hirefrank/confidant/issues` (searchable, URL-addressable). |
| 28 | `vulnerability_report_process` — published vuln-reporting process | MUST | Met | `SECURITY.md` "Reporting a vulnerability". |
| 29 | `vulnerability_report_private` — private reporting channel documented | MUST | Met | `SECURITY.md`: GitHub private vulnerability reporting (enabled on the repo) + email `frank@hirefrank.com`. |
| 30 | `vulnerability_report_response` — initial response ≤14 days | MUST | Met (weak) | `SECURITY.md` commits to acknowledgement within **5 business days** (<14 days). No vulnerability reports have been received in the last 6 months (project is newer). |

## Quality

| # | Criterion | Level | Status | Evidence |
|---|---|---|---|---|
| 31 | `build` — working automatic build system | MUST | Met | Cargo workspace; `cargo build`/`cargo install`; CI builds on ubuntu/macos/windows; `release.yml` (cargo-dist) builds release binaries. |
| 32 | `build_common_tools` — common build tools | SUGGESTED | Met | `cargo`/`rustc` (rustup). |
| 33 | `build_floss_tools` — buildable with only FLOSS tools | SHOULD | Met | Rust toolchain, Cargo, cargo-dist — all FLOSS. |
| 34 | `test` — automated FLOSS test suite, how to run it documented | MUST | Met | `cargo test --workspace --all-features --locked`; documented in `CONTRIBUTING.md` and `AGENTS.md`; run in `.github/workflows/ci.yml`. |
| 35 | `test_invocation` — invocable the standard way for the language | SHOULD | Met | `cargo test` (standard Cargo invocation). |
| 36 | `test_most` — suite covers most branches/inputs/functionality | SUGGESTED | Met (weak) | Extensive unit + contract tests plus golden `check --json` fixtures (`crates/*/tests`, `testdata/golden/`). **No coverage instrumentation** exists (no `cargo-llvm-cov`/Codecov), so "most branches" is asserted not measured. Optional hardening: add coverage to CI. |
| 37 | `test_continuous_integration` — CI runs tests frequently | SUGGESTED | Met | `ci.yml` on every push/PR to `main`, plus a nightly cron; runs fmt, clippy, full test suite, demo-vault `check`. |
| 38 | `test_policy` — policy that new functionality gets tests | MUST | Met | `AGENTS.md` code conventions ("add or update tests for every behaviour change"); `CONTRIBUTING.md` "Tests". |
| 39 | `tests_are_added` — policy followed in recent major changes | MUST | Met | Recent PRs ship tests: fuzz targets (#235), crypto rewrite/AAD, check-engine golden tests, `no-ai` leakage tests (#270), TUI tests. |
| 40 | `tests_documented_added` — test policy documented in change instructions | SUGGESTED | Met | `CONTRIBUTING.md` "Tests" section + PR-body template in `AGENTS.md`. |
| 41 | `warnings` — compiler warnings / safe mode / linter enabled | MUST | Met | `cargo clippy --workspace --all-targets --all-features -- -D warnings` in CI; `#![deny(unsafe_code)]` / `#![forbid(unsafe_code)]` in crates. |
| 42 | `warnings_fixed` — warnings addressed | MUST | Met | `RUSTFLAGS="-D warnings"` + clippy `-D warnings` in `ci.yml`; any warning fails the build. |
| 43 | `warnings_strict` — maximally strict with warnings | SUGGESTED | Met | All-targets, all-features, deny-warnings; fmt checked. |

## Security

| # | Criterion | Level | Status | Evidence |
|---|---|---|---|---|
| 44 | `know_secure_design` — primary dev knows secure design | MUST | Met | Questionnaire answer. Supporting evidence: `docs/crypto-design.md` (key hierarchy, AAD, threat model), `docs/threat-model-agents.md`, ADR process in `docs/architecture.md`. |
| 45 | `know_common_errors` — knows common vuln classes and mitigations | MUST | Met | Questionnaire answer. Evidence: threat models; privacy rules and `no-ai` allowlist (`AGENTS.md` hard rule 3, `docs/privacy.md`, `spec` §12); tests that prove `no-ai` content is excluded. |
| 46 | `crypto_published` — only reviewed, published crypto | MUST | Met | X25519 (`x25519-dalek`/`age`), XChaCha20-Poly1305 (`chacha20poly1305`), Ed25519 (`ed25519-dalek`), HKDF/HMAC-SHA-256 (`hkdf`/`hmac`/`sha2`), BIP-39 (`bip39`) — all public standards/audited crates (`crates/confidant-crypt/Cargo.toml`). |
| 47 | `crypto_call` — calls dedicated crypto software, doesn't roll its own | SHOULD | Met | `confidant-crypt` composes `age` + RustCrypto crates; no primitive is hand-implemented. |
| 48 | `crypto_floss` — crypto functionality implementable with FLOSS | MUST | Met | All crypto deps are FLOSS (age, RustCrypto, `getrandom`, `zeroize`). |
| 49 | `crypto_keylength` — ≥ NIST minimums through 2030, no smaller keys | MUST | Met | 256-bit ECC (X25519/Ed25519) and 256-bit AEAD keys; ≥ the 112-bit security floor NIST requires through 2030; no configuration permits shorter keys. |
| 50 | `crypto_working` — no broken algorithms/modes by default | MUST | Met | AEAD only (XChaCha20-Poly1305); no MD4/MD5/DES/RC4/Dual_EC_DRBG. |
| 51 | `crypto_weaknesses` — avoid algorithms with serious weaknesses | SHOULD | Met | No SHA-1/MD5 for security, no CBC/SSH-style modes; SHA-256/HKDF-HMAC used for derivation/addressing. |
| 52 | `crypto_pfs` — forward secrecy for key agreement | SHOULD | **N/A** | There is no interactive session/key-agreement protocol. X25519 + age is used for **one-shot key wrapping** of per-client data keys; content is protected by XChaCha20-Poly1305. Long-term-key compromise is explicitly in scope and documented in `docs/crypto-design.md` §11. Mark N/A with this reasoning. |
| 53 | `crypto_password_storage` — passwords stored as salted KDF hashes | MUST | **N/A** | The software stores no user passwords for external-user authentication; operator/device keys live in the OS keychain or on disk (`docs/crypto-design.md` §4). |
| 54 | `crypto_random` — keys/nonces from a CSPRNG | MUST | Met | `getrandom`/`rand` `OsRng`; `zeroize` for secret hygiene; no non-crypto RNG for key material. |
| 55 | `delivery_mitm` — delivery counters MITM | MUST | Met | HTTPS/TLS for repo, crates.io, and the `curl --proto '=https' --tlsv1.2` installer; per-artifact `.sha256` files; build-provenance attestations via `actions/attest-build-provenance` (`release.yml`). |
| 56 | `delivery_unsigned` — no unsigned hash fetched over http | MUST | Met | All checksums are served over HTTPS (GitHub Releases) and published alongside artifacts; no http hash retrieval. |
| 57 | `vulnerabilities_fixed_60_days` — no unpatched medium+ vuln older than 60 days | MUST | Met | `cargo audit` runs in CI (daily cron) and Dependabot security updates are enabled; Scorecard `Vulnerabilities` = 10 (0 known). No known unpatched medium+ issues. |
| 58 | `vulnerabilities_critical_fixed` — criticals fixed rapidly | SHOULD | Met | `SECURITY.md` "What to expect": critical issues fixed ASAP within the 90-day coordinated-disclosure window. No criticals reported to date. |
| 59 | `no_leaked_credentials` — no valid private credential in public repos | MUST | Met | No secrets in repo (fake-data rule, `AGENTS.md` hard rule 4); repo settings show secret scanning **enabled** and push protection **enabled**. |

## Analysis

| # | Criterion | Level | Status | Evidence |
|---|---|---|---|---|
| 60 | `static_analysis` — static analysis tool applied before release | MUST | Met | `cargo clippy` (`-D warnings`, all targets/features) on every push/PR; plus `cargo-deny` and `cargo-audit`; Scorecard uploads SARIF to code scanning (`scorecard.yml`). |
| 61 | `static_analysis_common_vulnerabilities` — rules for common vulns | SUGGESTED | Met (weak) | Satisfied by clippy's correctness/security-relevant lints, `unsafe` bans, and overflow checks; **no dedicated vulnerability SAST** (CodeQL/Semgrep). Scorecard `SAST` = 0 for that reason. Consider adding CodeQL as optional hardening. |
| 62 | `static_analysis_fixed` — medium+ SAST findings fixed timely | MUST | Met | No confirmed medium+ exploitable findings to date (vacuously satisfied); CI fails on any new lint/deny/audit finding. |
| 63 | `static_analysis_often` — SAST on every commit or daily | SUGGESTED | Met | clippy runs on every push/PR; the CI workflow also runs on a nightly cron. |
| 64 | `dynamic_analysis` — dynamic tool used before major release | SUGGESTED | Met | `fuzz/` cargo-fuzz targets (`ledger_line`, `envelope_decode`), documented run commands in `CONTRIBUTING.md`; nightly CI exercises the binaries. (Harnesses run manually, not in CI — see notes.) |
| 65 | `dynamic_analysis_unsafe` — memory-safety dynamic tooling | SUGGESTED | **N/A** | Confidant is written in Rust and the crates use `#![deny(unsafe_code)]`/`#![forbid(unsafe_code)]`; no memory-unsafe language is used. |
| 66 | `dynamic_analysis_enable_assertions` — assertions enabled in some dynamic config | SUGGESTED | Met | Rust's test/debug profile enables `debug_assertions` (and overflow checks); tests run in CI with them on, while `release`/`dist` builds have them off. |
| 67 | `dynamic_analysis_fixed` — medium+ dynamic findings fixed timely | MUST | Met | No confirmed medium+ dynamic findings to date; fuzz crashes are treated as bugs and fixed before release (see #235/#269). |

---

## Weakest claims (review before submitting)

These are Met but not airtight; word them carefully or add the optional hardening.

1. **`static_analysis_common_vulnerabilities` (#61)** — the only tool is clippy + cargo-deny/audit.
   Scorecard reports `SAST 0` because it looks for a CodeQL-class scanner. Adding a CodeQL (or
   Semgrep) workflow, or `cargo-geiger`, would make this unambiguous. Not required to pass, but it
   is the claim most likely to look stretched.
2. **`test_most` (#36)** — the suite is broad (unit + CLI contract + golden fixtures) but coverage
   is not measured. Optional: add `cargo-llvm-cov` to CI.
3. **`report_responses` / `enhancement_responses` / `vulnerability_report_response` (#25/#26/#30)** —
   the project is ~1 week old, so there is no 2–12 month history. State that plainly on the form.
4. **`dynamic_analysis` (#64)** — harnesses exist and are documented, but are deliberately not run
   in CI (`AGENTS.md` notes fuzz is a manual, nightly-toolchain step). This is acceptable for a
   SUGGESTED criterion, but say how you run them.

## Previously-flagged gaps — now resolved

Issue #237 anticipated these gaps. All three are closed and the criteria are Met:

| Gap | Issue | Status | Evidence |
|---|---|---|---|
| Branch protection | [#234](https://github.com/hirefrank/confidant/issues/234) — closed | Met | Ruleset `Protect main` (id 25103877), *active*: requires a PR, blocks deletion and non-fast-forward. `gh api repos/hirefrank/confidant/rules/branches/main` lists `pull_request`, `deletion`, `non_fast_forward`. |
| Fuzzing | [#235](https://github.com/hirefrank/confidant/issues/235) — closed | Met | `fuzz/fuzz_targets/ledger_line.rs`, `fuzz/fuzz_targets/envelope_decode.rs`, corpus generator, run docs in `CONTRIBUTING.md`. Scorecard `Fuzzing` = 10. |
| Scorecard | [#236](https://github.com/hirefrank/confidant/issues/236) — closed | Met | `.github/workflows/scorecard.yml` (weekly + on push), README badge; latest published score 6.4 at 2026-10-14. |
| Dependency updates | `.github/dependabot.yml` | Met | Weekly Cargo + monthly GitHub Actions updates; Dependabot security updates enabled in repo settings. |

No **Unmet** criterion currently maps to an open issue. There are no NEW gaps that need filing to
earn the badge; the items in *Weakest claims* are optional hardening, not blockers.

## Not passing-badge criteria (context only)

Recorded so they are not confused with criteria, and because a reviewer will see them in Scorecard:

- Scorecard `Code-Review 0` and `Branch-Protection 3`: the repo requires a PR (ruleset active) but
  `required_approving_review_count` is `0` — a solo maintainer, so no second reviewer. Fine for the
  passing badge; blocks the Scorecard branch-protection/Code-Review checks.
- Scorecard `Signed-Releases 0`: an `attest` job (build provenance) exists in `release.yml`, but
  Scorecard did not detect signed/provenance artifacts — likely because the last tag predates the
  attestation job or Scorecard does not read GitHub attestation records. Not a passing criterion
  (`delivery_mitm`/`delivery_unsigned` are Met). Worth a follow-up if a higher badge or a cleaner
  Scorecard is wanted.
- Scorecard `CII-Best-Practices: badge detected: InProgress` appears to be stale/erroneous: querying
  `www.bestpractices.dev/projects.json` returns no project for `hirefrank/confidant`. Once enrolled
  and passing, this should flip to `Passing` and the Scorecard score will rise.

## Enrollment (needs Frank's GitHub login — cannot be done by an agent)

1. Sign in at https://www.bestpractices.dev with the GitHub account that owns `hirefrank/confidant`.
2. Create the project page (https://www.bestpractices.dev/en/projects/new), pointing at
   `https://github.com/hirefrank/confidant`.
3. Walk the questionnaire using this table; mark N/A for #22, #52, #53, #65 with the justifications above.
4. Add the resulting badge to `README.md` (next to the Scorecard badge) and close
   [#237](https://github.com/hirefrank/confidant/issues/237) with the badge URL.

<!-- ci-326 probe: docs-only change, do not merge -->
