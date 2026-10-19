//! Quick capture (#556 phase 3): `s` session, `t` touch, `n` note.
//!
//! Each capture collects the fields the CLI needs, pre-filling the selected
//! person's opaque id so the operator never types a ULID. Nothing is written
//! until the operator confirms the CLI's own `--dry-run` preview with `y`; the
//! real write goes out through the same `confidant` subprocess contract
//! (`--json --no-input`, one commit per write).
//!
//! A note body is the one field the CLI only takes from a file
//! (`note add --body-file`), so it is staged in the same 0600 gitignored
//! scratch the conflict/edit flows use (`#455`, `#556` phase 2) and removed on
//! every exit path. This module never links `confidant-core`: the only file it
//! touches is this crate's own scratch, and nothing here logs the captured
//! text (the manual `Debug` impl redacts it).

use std::path::{Path, PathBuf};

use crate::apply::DryRunChange;

/// Which quick-capture surface is open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureKind {
    /// `log session <person> <duration> [tag] [--note …]`.
    Session,
    /// `log touch <person> <kind> [--note …]`.
    Touch,
    /// `note add --person <person> … --body-file <scratch>`.
    Note,
}

impl CaptureKind {
    /// The modal title.
    pub fn title(self) -> &'static str {
        match self {
            Self::Session => "Log session",
            Self::Touch => "Log touch",
            Self::Note => "Add note",
        }
    }

    /// The noun used in result messages.
    pub fn noun(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Touch => "touch",
            Self::Note => "note",
        }
    }

    /// The fields this surface collects, in focus order.
    fn fields(self) -> Vec<CaptureField> {
        match self {
            Self::Session => vec![
                text(FieldId::Duration, "duration", true, "60m or 1h30m"),
                text(
                    FieldId::Tag,
                    "tag",
                    false,
                    "paid | pps | comp (blank for none)",
                ),
                text(FieldId::Date, "date", false, "YYYY-MM-DD (blank for today)"),
                text(
                    FieldId::NoteText,
                    "note",
                    false,
                    "inline note (blank for none)",
                ),
            ],
            Self::Touch => vec![
                text(
                    FieldId::TouchKind,
                    "kind",
                    true,
                    "call|text|email|meet|meal|event|gift|other",
                ),
                text(FieldId::Date, "date", false, "YYYY-MM-DD (blank for today)"),
                text(
                    FieldId::NoteText,
                    "note",
                    false,
                    "inline note (blank for none)",
                ),
            ],
            Self::Note => vec![
                text(
                    FieldId::Body,
                    "body",
                    true,
                    "one-line body (edit after for prose)",
                ),
                text(FieldId::Date, "date", false, "YYYY-MM-DD (blank for today)"),
                toggle(FieldId::NoAi, "no-ai", "space toggles (hide from agents)"),
            ],
        }
    }
}

/// Which capture step is on screen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapturePhase {
    /// Collecting fields; `Enter` runs the `--dry-run` preview.
    #[default]
    Editing,
    /// The dry-run preview is on screen; `y` writes, any other key cancels.
    Preview,
}

/// Identifies a field without depending on its display label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldId {
    Duration,
    Tag,
    Date,
    TouchKind,
    NoteText,
    Body,
    NoAi,
}

/// Whether a field is free text or a boolean toggle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Toggle,
}

/// One editable field in the capture form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureField {
    pub id: FieldId,
    pub label: &'static str,
    pub kind: FieldKind,
    /// A non-empty value is required before the preview runs (toggles are
    /// never required).
    pub required: bool,
    pub value: String,
    /// Toggle state; ignored for text fields.
    pub enabled: bool,
    pub hint: &'static str,
}

fn text(id: FieldId, label: &'static str, required: bool, hint: &'static str) -> CaptureField {
    CaptureField {
        id,
        label,
        kind: FieldKind::Text,
        required,
        value: String::new(),
        enabled: false,
        hint,
    }
}

fn toggle(id: FieldId, label: &'static str, hint: &'static str) -> CaptureField {
    CaptureField {
        id,
        label,
        kind: FieldKind::Toggle,
        required: false,
        value: String::new(),
        enabled: false,
        hint,
    }
}

/// The in-flight quick capture.
///
/// Field values and the dry-run `preview` hold operator plaintext (a note
/// body, session note text), so the manual [`std::fmt::Debug`] impl redacts
/// them: nothing here may reach logs or a panic message.
#[derive(Clone, PartialEq)]
pub struct Capture {
    pub kind: CaptureKind,
    pub person_id: String,
    pub person_name: Option<String>,
    pub fields: Vec<CaptureField>,
    pub focus: usize,
    pub phase: CapturePhase,
    pub preview: Vec<DryRunChange>,
    /// The staged note body, for `note add --body-file`. `None` for the
    /// inline surfaces (session/touch), whose note travels as an argument.
    pub scratch: Option<PathBuf>,
    /// A validation or CLI error shown inline under the form; the modal stays
    /// open so the operator can fix the field.
    pub error: Option<String>,
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted: Vec<(FieldId, &str)> = self
            .fields
            .iter()
            .map(|field| (field.id, "<redacted>"))
            .collect();
        f.debug_struct("Capture")
            .field("kind", &self.kind)
            .field("person_id", &self.person_id)
            .field("person_name", &self.person_name)
            .field("fields", &redacted)
            .field("focus", &self.focus)
            .field("phase", &self.phase)
            .field("preview", &self.preview.len())
            .field("scratch", &self.scratch)
            .field("error", &self.error)
            .finish()
    }
}

impl Capture {
    /// Build a fresh capture for `kind`, pre-filled with the selected person.
    pub fn new(kind: CaptureKind, person_id: String, person_name: Option<String>) -> Self {
        Self {
            kind,
            person_id,
            person_name,
            fields: kind.fields(),
            focus: 0,
            phase: CapturePhase::Editing,
            preview: Vec::new(),
            scratch: None,
            error: None,
        }
    }

    /// The value of a text field, or an empty string when absent.
    pub fn value(&self, id: FieldId) -> &str {
        self.fields
            .iter()
            .find(|field| field.id == id)
            .map(|field| field.value.as_str())
            .unwrap_or("")
    }

    /// The state of a toggle field, or `false` when absent.
    pub fn enabled(&self, id: FieldId) -> bool {
        self.fields
            .iter()
            .find(|field| field.id == id)
            .map(|field| field.enabled)
            .unwrap_or(false)
    }

    /// The label of the first empty required field, if any.
    pub fn first_missing(&self) -> Option<&'static str> {
        self.fields
            .iter()
            .find(|field| {
                field.kind == FieldKind::Text && field.required && field.value.trim().is_empty()
            })
            .map(|field| field.label)
    }

    /// Move focus, wrapping. No-op when there are no fields.
    pub fn focus_next(&mut self, forward: bool) {
        if self.fields.is_empty() {
            return;
        }
        self.focus = if forward {
            (self.focus + 1) % self.fields.len()
        } else {
            (self.focus + self.fields.len() - 1) % self.fields.len()
        };
    }

    /// Append a character to the focused text field (no-op on a toggle).
    pub fn push_char(&mut self, c: char) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            if field.kind == FieldKind::Text {
                field.value.push(c);
            }
        }
    }

    /// Delete the last character of the focused text field (no-op on a toggle).
    pub fn backspace(&mut self) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            if field.kind == FieldKind::Text {
                field.value.pop();
            }
        }
    }

    /// Space: toggle a focused toggle field, otherwise type a space.
    pub fn space(&mut self) {
        match self.fields.get_mut(self.focus) {
            Some(field) if field.kind == FieldKind::Toggle => field.enabled = !field.enabled,
            Some(field) => field.value.push(' '),
            None => {}
        }
    }

    /// The CLI argv for this capture. `scratch` is the staged note body file
    /// (only `note add` uses it; the inline surfaces ignore it).
    ///
    /// No `--dry-run` here: [`crate::apply::run_write_step`] adds it for the
    /// preview and omits it for the confirmed write.
    pub fn argv(&self, scratch: Option<&str>) -> Vec<String> {
        match self.kind {
            CaptureKind::Session => {
                let mut argv = vec![
                    "log".to_owned(),
                    "session".to_owned(),
                    self.person_id.clone(),
                    self.value(FieldId::Duration).trim().to_owned(),
                ];
                let tag = self.value(FieldId::Tag).trim();
                if !tag.is_empty() {
                    argv.push(tag.to_owned());
                }
                push_opt(&mut argv, "--date", self.value(FieldId::Date).trim());
                push_opt(&mut argv, "--note", self.value(FieldId::NoteText));
                argv
            }
            CaptureKind::Touch => {
                let mut argv = vec![
                    "log".to_owned(),
                    "touch".to_owned(),
                    self.person_id.clone(),
                    self.value(FieldId::TouchKind).trim().to_owned(),
                ];
                push_opt(&mut argv, "--date", self.value(FieldId::Date).trim());
                push_opt(&mut argv, "--note", self.value(FieldId::NoteText));
                argv
            }
            CaptureKind::Note => {
                let mut argv = vec![
                    "note".to_owned(),
                    "add".to_owned(),
                    "--person".to_owned(),
                    self.person_id.clone(),
                ];
                push_opt(&mut argv, "--date", self.value(FieldId::Date).trim());
                if self.enabled(FieldId::NoAi) {
                    argv.push("--no-ai".to_owned());
                }
                argv.push("--body-file".to_owned());
                argv.push(scratch.unwrap_or_default().to_owned());
                argv
            }
        }
    }
}

/// Push `--flag value` unless `value` is blank. The value is passed through
/// untouched (note text keeps its whitespace); only the emptiness test trims.
fn push_opt(argv: &mut Vec<String>, flag: &str, value: &str) {
    if !value.trim().is_empty() {
        argv.push(flag.to_owned());
        argv.push(value.to_owned());
    }
}

/// The scratch file for a captured note body:
/// `<vault>/.confidant/conflicts/<person-id>/capture.md`.
///
/// Reuses the conflict scratch directory (`#455`, `#556` phase 2) rather than
/// inventing a new root; the file name never collides with the CLI's
/// `ours.md`/`theirs.md`/`merged.md` or the TUI's `edit.md`.
///
/// Returns `None` for an id that is not a single safe path component, so a
/// malformed id can never escape `.confidant/`.
pub fn scratch_path(vault_root: &Path, person_id: &str) -> Option<PathBuf> {
    if person_id.is_empty()
        || person_id == "."
        || person_id == ".."
        || person_id.contains('/')
        || person_id.contains('\\')
        || person_id.contains('\0')
    {
        return None;
    }
    Some(
        vault_root
            .join(".confidant")
            .join("conflicts")
            .join(person_id)
            .join("capture.md"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proposals::test_temp_dir;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn session_argv_prefills_person_and_orders_positionals() {
        let mut capture = Capture::new(
            CaptureKind::Session,
            "p-01ABC".to_owned(),
            Some("Ada Example".to_owned()),
        );
        capture.fields[0].value = "60m".to_owned();
        capture.fields[1].value = "paid".to_owned();
        capture.fields[2].value = "2026-10-13".to_owned();
        capture.fields[3].value = "discussed goals".to_owned();
        assert_eq!(
            capture.argv(None),
            s(&[
                "log",
                "session",
                "p-01ABC",
                "60m",
                "paid",
                "--date",
                "2026-10-13",
                "--note",
                "discussed goals",
            ])
        );
    }

    #[test]
    fn session_argv_omits_blank_optional_fields() {
        let mut capture = Capture::new(CaptureKind::Session, "p-01ABC".to_owned(), None);
        capture.fields[0].value = " 45m ".to_owned();
        assert_eq!(capture.argv(None), s(&["log", "session", "p-01ABC", "45m"]));
    }

    #[test]
    fn touch_argv_carries_person_kind_date_and_note() {
        let mut capture = Capture::new(CaptureKind::Touch, "p-01ABC".to_owned(), None);
        capture.fields[0].value = "meal".to_owned();
        capture.fields[2].value = "lunch".to_owned();
        assert_eq!(
            capture.argv(None),
            s(&["log", "touch", "p-01ABC", "meal", "--note", "lunch"])
        );
    }

    #[test]
    fn note_argv_uses_body_file_and_toggles_no_ai() {
        let mut capture = Capture::new(CaptureKind::Note, "p-01ABC".to_owned(), None);
        capture.fields[0].value = "one line".to_owned();
        capture.fields[2].enabled = true;
        assert_eq!(
            capture.argv(Some("/tmp/x/capture.md")),
            s(&[
                "note",
                "add",
                "--person",
                "p-01ABC",
                "--no-ai",
                "--body-file",
                "/tmp/x/capture.md",
            ])
        );
    }

    #[test]
    fn required_fields_gate_the_preview() {
        let mut capture = Capture::new(CaptureKind::Session, "p-01ABC".to_owned(), None);
        assert_eq!(capture.first_missing(), Some("duration"));
        capture.fields[0].value = "60m".to_owned();
        assert_eq!(capture.first_missing(), None);
        // Whitespace is not a value.
        capture.fields[0].value = "   ".to_owned();
        assert_eq!(capture.first_missing(), Some("duration"));
    }

    #[test]
    fn focus_wraps_and_edits_the_focused_field_only() {
        let mut capture = Capture::new(CaptureKind::Touch, "p-01ABC".to_owned(), None);
        capture.push_char('c');
        assert_eq!(capture.value(FieldId::TouchKind), "c");
        capture.focus_next(true);
        capture.push_char('x');
        assert_eq!(capture.value(FieldId::Date), "x");
        assert_eq!(capture.value(FieldId::TouchKind), "c");
        capture.backspace();
        assert_eq!(capture.value(FieldId::Date), "");
        // Wrap back to the first field.
        capture.focus_next(true);
        capture.focus_next(true);
        assert_eq!(capture.focus, 0);
    }

    #[test]
    fn space_toggles_a_toggle_and_types_in_text() {
        let mut capture = Capture::new(CaptureKind::Note, "p-01ABC".to_owned(), None);
        capture.space();
        assert_eq!(capture.value(FieldId::Body), " ");
        capture.focus = 2;
        capture.space();
        assert!(capture.enabled(FieldId::NoAi));
        capture.space();
        assert!(!capture.enabled(FieldId::NoAi));
    }

    #[test]
    fn scratch_path_is_a_single_component_under_conflicts() {
        let root = Path::new("/vault");
        assert_eq!(
            scratch_path(root, "p-01ABC").unwrap(),
            Path::new("/vault/.confidant/conflicts/p-01ABC/capture.md")
        );
        assert_eq!(scratch_path(root, ""), None);
        assert_eq!(scratch_path(root, ".."), None);
        assert_eq!(scratch_path(root, "../evil"), None);
        assert_eq!(scratch_path(root, "a/b"), None);
    }

    #[test]
    fn capture_debug_redacts_plaintext() {
        let mut capture = Capture::new(CaptureKind::Note, "p-01ABC".to_owned(), None);
        capture.fields[0].value = "SENTINEL-BODY".to_owned();
        capture.preview.push(DryRunChange {
            path: "people/p-01ABC/notes/n-1.md".to_owned(),
            action: "add".to_owned(),
            content: "SENTINEL-PREVIEW".to_owned(),
        });
        let debug = format!("{capture:?}");
        assert!(!debug.contains("SENTINEL"), "plaintext leaked: {debug}");
        assert!(debug.contains("p-01ABC"), "{debug}");
    }

    #[test]
    fn scratch_roundtrips_through_the_edit_plumbing() {
        let root = test_temp_dir("tui-capture-scratch");
        let path = scratch_path(&root, "p-01ABC").unwrap();
        crate::edit::write_scratch(&path, "captured body").unwrap();
        assert_eq!(crate::edit::read_scratch(&path).unwrap(), "captured body");
        crate::edit::remove_scratch(&path);
        assert!(!path.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
