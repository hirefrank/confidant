//! THROWAWAY SPIKE — not a product crate.
//!
//! A minimal Rune desktop shell over Confidant: it loads the people roster
//! from a vault (default: the checked-in demo vault, fake data only) via
//! `confidant-core` and renders a selectable people list with a detail pane.
//! See `docs/research/rune-desktop-app-spike.md` for findings.
//!
//! Run headless (no display needed) from this directory:
//!   cargo run -- --snap spike.png --tree spike-tree.txt [--scene first]
//! Or run the scripted-input test: `cargo test`.
//!
//! Vault path: `CONFIDANT_SPIKE_VAULT`, else `../../examples/demo-vault`
//! relative to this crate. Never point it at a real vault.

use confidant_core::roster::build_roster;
use confidant_core::vault::load_vault;
use confidant_core::{PackScope, RecordId};
use rune::tok::{self, type_};
use rune::{col, el, row, text, AppSpec, Cx, El};
use std::path::PathBuf;

#[derive(Clone, Debug)]
struct Person {
    id: String,
    name: String,
    detail: String,
}

#[derive(Default)]
struct State {
    people: Vec<Person>,
    selected: Option<usize>,
}

fn vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("CONFIDANT_SPIKE_VAULT") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo-vault")
}

/// Operator view of the people roster: `for_operator = true`, so the
/// operator's own app sees every record, exactly like the TUI does.
/// (An agent-driven headless render is a different audience: see the
/// findings doc on `no-ai` — agent-visible output must use the cleared
/// roster instead.)
fn load_people(vault_root: &std::path::Path) -> Vec<Person> {
    let vault = load_vault(vault_root).expect("vault loads");
    let roster = build_roster(&vault, Some("person"), &PackScope::All, true);
    roster
        .records
        .iter()
        .map(|entry| {
            let detail = RecordId::parse(&entry.id)
                .ok()
                .and_then(|id| vault.records.get(&id))
                .map(|rec| {
                    ["title", "company", "location"]
                        .iter()
                        .filter_map(|k| rec.field(k))
                        .collect::<Vec<_>>()
                        .join(" · ")
                })
                .unwrap_or_default();
            Person {
                id: entry.id.clone(),
                name: entry.name.clone(),
                detail,
            }
        })
        .collect()
}

fn view(s: &State, _: &mut Cx<State>) -> El {
    let t = tok::theme(true);
    let mut list = col().gap(4.0);
    for (i, p) in s.people.iter().enumerate() {
        let selected = s.selected == Some(i);
        let name = text(&p.name).font(type_::BODY).color(t.text);
        let item = row()
            .key(format!("person-{}", p.id))
            .w_full()
            .gap(8.0)
            .fill(if selected { t.card } else { t.bg })
            .on_press(move |s: &mut State| s.selected = Some(i))
            .child(name);
        list = list.child(item);
    }
    let detail = match s.selected.and_then(|i| s.people.get(i)) {
        Some(p) => col()
            .gap(4.0)
            .child(text(&p.name).font(type_::TITLE).color(t.text))
            .child(text(&p.detail).font(type_::BODY).color(t.text_secondary)),
        None => col().child(
            text("Select a person")
                .font(type_::BODY)
                .color(t.text_secondary),
        ),
    };
    row()
        .w_full()
        .h_full()
        .fill(t.bg)
        .child(el().w(300.0).child(list))
        .child(el().grow(1.0).child(detail))
}

fn init_state() -> State {
    State {
        people: load_people(&vault_path()),
        selected: None,
    }
}

fn main() {
    rune::run(AppSpec::<State> {
        scenes: &[("first", |s| s.selected = Some(0))],
        ..AppSpec::new("Confidant (spike)", (900.0, 600.0), init_state, view)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune::{Env, Runtime};

    fn test_state() -> State {
        State {
            people: load_people(&vault_path()),
            selected: None,
        }
    }

    #[test]
    fn roster_loads_demo_people() {
        let s = test_state();
        assert!(!s.people.is_empty(), "demo vault has people");
        assert!(
            s.people.iter().any(|p| p.name == "Dana Example"),
            "expected Dana Example in {:?}",
            s.people.iter().map(|p| &p.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn tapping_a_row_selects_it() {
        let env = Env {
            system_dark: true,
            scale: 2.0,
        };
        let mut rt = Runtime::new(test_state(), view, (900.0, 600.0), env);
        rt.frame(0.0);
        assert_eq!(rt.state.selected, None);
        let first_id = rt.state.people[0].id.clone();
        let (x, y) = rt.find(&format!("person-{first_id}")).unwrap();
        rt.pointer_down(x, y);
        rt.pointer_up(x, y);
        rt.frame(1.0 / 60.0);
        assert_eq!(rt.state.selected, Some(0));
    }
}
