//! Split a git-conflicted file into its two sides.
//!
//! Pure text reconstruction for merge-conflict resolution
//! (#451, part of #219). It operates on file text only: no I/O, and never
//! logs file content.

use std::fmt;

use crate::record::has_conflict_markers;

/// The two full file versions reconstructed from a conflicted file.
///
/// Common lines appear in both sides byte-for-byte; each hunk contributes
/// its `<<<<<<<` lines to [`ConflictSides::ours`] and its `>>>>>>>` lines
/// to [`ConflictSides::theirs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictSides {
    /// The `<<<<<<<` side, with common lines included.
    pub ours: String,
    /// The `>>>>>>>` side, with common lines included.
    pub theirs: String,
    /// Label from the `<<<<<<<` line of the first hunk (e.g. `HEAD`).
    pub ours_label: String,
    /// Label from the `>>>>>>>` line of the first hunk (e.g. `feature/x`).
    pub theirs_label: String,
}

/// Why [`split_conflict_sides`] could not reconstruct both sides.
///
/// Errors are values, never panics, and carry no file content: the
/// [`ConflictSplitError::Malformed`] reason is a static structural
/// description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictSplitError {
    /// The cheap [`has_conflict_markers`] pre-check found no markers.
    NoMarkers,
    /// Markers are present but the hunk structure is broken
    /// (nested, unterminated, or misplaced markers).
    Malformed(&'static str),
    /// More than [`MAX_HUNKS`] hunks in one file.
    TooManyHunks,
    /// A marker uses a run length other than 7 (git's
    /// `-X conflict-marker-size`); only size 7 is supported.
    UnsupportedMarkerSize,
}

impl fmt::Display for ConflictSplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConflictSplitError::NoMarkers => write!(f, "no conflict markers found"),
            ConflictSplitError::Malformed(reason) => {
                write!(f, "malformed conflict markers: {reason}")
            }
            ConflictSplitError::TooManyHunks => {
                write!(f, "too many conflict hunks (max {MAX_HUNKS})")
            }
            ConflictSplitError::UnsupportedMarkerSize => {
                write!(
                    f,
                    "unsupported conflict marker size (only size 7 is supported)"
                )
            }
        }
    }
}

impl std::error::Error for ConflictSplitError {}

/// Marker run length git writes by default.
const MARKER_SIZE: usize = 7;
/// Fail-closed cap on hunks per file (CD8: more than 20 is an error).
const MAX_HUNKS: usize = 20;

/// What a single line looks like to the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker<'a> {
    /// `<<<<<<<` plus the label rest.
    Start(&'a str),
    /// `>>>>>>>` plus the label rest.
    End(&'a str),
    /// `|||||||` (diff3 base) plus the label rest.
    Base(&'a str),
    /// Exactly `=======`.
    Sep,
    /// Separator-shaped but invalid: `=======` with trailing text.
    /// An 8+ run of `=` is [`Marker::BadSize`] instead.
    BadSep,
    /// A run of a marker char whose length is not 7.
    BadSize(char),
    /// Ordinary line. Any `=` line outside a hunk is text: a setext
    /// `=======` underline is not a conflict marker.
    Text,
}

/// Classify one `\r`-stripped line.
fn classify(line: &str) -> Marker<'_> {
    let bytes = line.as_bytes();
    let Some(&first) = bytes.first() else {
        return Marker::Text;
    };
    let run = bytes.iter().take_while(|&&b| b == first).count();
    match first {
        b'<' | b'>' | b'|' => {
            if run != MARKER_SIZE {
                return Marker::BadSize(first as char);
            }
            // Byte index 7 is a char boundary: the first 7 bytes are ASCII.
            let rest = &line[MARKER_SIZE..];
            match first {
                b'<' => Marker::Start(rest),
                b'>' => Marker::End(rest),
                _ => Marker::Base(rest),
            }
        }
        b'=' => {
            if line.len() == MARKER_SIZE {
                Marker::Sep
            } else if run == MARKER_SIZE {
                Marker::BadSep
            } else if run > MARKER_SIZE {
                Marker::BadSize('=')
            } else {
                Marker::Text
            }
        }
        _ => Marker::Text,
    }
}

/// Validate a marker label rest: empty (bare `<<<<<<<`) or a space plus
/// the label. Anything else is not a git marker.
fn label(rest: &str) -> Result<&str, ConflictSplitError> {
    if rest.is_empty() {
        Ok("")
    } else if let Some(l) = rest.strip_prefix(' ') {
        Ok(l)
    } else {
        Err(ConflictSplitError::Malformed("invalid marker label"))
    }
}

/// Reconstruct the two full file versions from a git-conflicted text.
///
/// Common lines go to both sides; a diff3 base block (`|||||||` up to
/// `=======`) is ignored. Lines are split on `\n` keeping any trailing
/// `\r`, so both sides preserve the original bytes exactly, including
/// whether the file ends with a newline. Labels come from the first
/// hunk's `<<<<<<<` / `>>>>>>>` lines.
///
/// ```
/// # use confidant_core::conflict::split_conflict_sides;
/// let text = "common\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch\n";
/// let sides = split_conflict_sides(text).unwrap();
/// assert_eq!(sides.ours, "common\nours\n");
/// assert_eq!(sides.theirs, "common\ntheirs\n");
/// assert_eq!(sides.ours_label, "HEAD");
/// assert_eq!(sides.theirs_label, "branch");
/// ```
pub fn split_conflict_sides(text: &str) -> Result<ConflictSides, ConflictSplitError> {
    // Cheap pre-check; the full parse below is authoritative.
    if !has_conflict_markers(text) {
        return Err(ConflictSplitError::NoMarkers);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        Ours,
        Base,
        Theirs,
    }
    use State::{Base, Normal, Ours, Theirs};

    let mut ours: Vec<&str> = Vec::new();
    let mut theirs: Vec<&str> = Vec::new();
    let mut ours_label: Option<&str> = None;
    let mut theirs_label: Option<&str> = None;
    let mut hunks = 0usize;
    let mut state = Normal;

    for raw in text.split('\n') {
        // Marker matching ignores a trailing \r; content lines keep it so
        // the reconstructed sides are byte-exact.
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        match state {
            Normal => match classify(line) {
                Marker::Start(rest) => {
                    let l = label(rest)?;
                    hunks += 1;
                    if hunks > MAX_HUNKS {
                        return Err(ConflictSplitError::TooManyHunks);
                    }
                    if ours_label.is_none() {
                        ours_label = Some(l);
                    }
                    state = Ours;
                }
                Marker::End(_) => {
                    return Err(ConflictSplitError::Malformed("end marker without start"));
                }
                Marker::Base(_) => {
                    return Err(ConflictSplitError::Malformed("base marker without start"));
                }
                // A setext `=======` (or any `=` run) outside a hunk is
                // ordinary text.
                Marker::Sep | Marker::BadSep | Marker::BadSize('=') | Marker::Text => {
                    ours.push(raw);
                    theirs.push(raw);
                }
                Marker::BadSize(_) => return Err(ConflictSplitError::UnsupportedMarkerSize),
            },
            Ours => match classify(line) {
                Marker::Sep => state = Theirs,
                Marker::Base(rest) => {
                    label(rest)?;
                    state = Base;
                }
                Marker::Start(_) => {
                    return Err(ConflictSplitError::Malformed("nested start marker"));
                }
                Marker::End(_) => {
                    return Err(ConflictSplitError::Malformed(
                        "end marker without separator",
                    ));
                }
                Marker::BadSep => {
                    return Err(ConflictSplitError::Malformed("invalid separator"));
                }
                Marker::BadSize(_) => return Err(ConflictSplitError::UnsupportedMarkerSize),
                Marker::Text => ours.push(raw),
            },
            Base => match classify(line) {
                // The diff3 base block is ignored: skip to the separator.
                Marker::Sep => state = Theirs,
                Marker::Start(_) | Marker::End(_) | Marker::Base(_) => {
                    return Err(ConflictSplitError::Malformed("nested marker in base block"));
                }
                Marker::BadSep => {
                    return Err(ConflictSplitError::Malformed("invalid separator"));
                }
                Marker::BadSize(_) => return Err(ConflictSplitError::UnsupportedMarkerSize),
                Marker::Text => {}
            },
            Theirs => match classify(line) {
                Marker::End(rest) => {
                    let l = label(rest)?;
                    if theirs_label.is_none() {
                        theirs_label = Some(l);
                    }
                    state = Normal;
                }
                Marker::Start(_) => {
                    return Err(ConflictSplitError::Malformed("nested start marker"));
                }
                Marker::Sep | Marker::BadSep | Marker::BadSize('=') => {
                    return Err(ConflictSplitError::Malformed("separator without start"));
                }
                Marker::Base(_) => {
                    return Err(ConflictSplitError::Malformed("base marker after separator"));
                }
                Marker::BadSize(_) => return Err(ConflictSplitError::UnsupportedMarkerSize),
                Marker::Text => theirs.push(raw),
            },
        }
    }

    match state {
        Normal => {
            if hunks == 0 {
                // Unreachable when the pre-check passed: any <<<<<<</>>>>>>>
                // line either starts a hunk or errors above. Fail closed.
                return Err(ConflictSplitError::NoMarkers);
            }
        }
        _ => return Err(ConflictSplitError::Malformed("unterminated hunk")),
    }

    Ok(ConflictSides {
        ours: ours.join("\n"),
        theirs: theirs.join("\n"),
        ours_label: ours_label.unwrap_or_default().to_string(),
        theirs_label: theirs_label.unwrap_or_default().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_hunk_two_sides() {
        let text = concat!(
            "---\n",
            "id: p-01J0000000000000000000000\n",
            "type: person\n",
            "name: Ada Example\n",
            "---\n",
            "<<<<<<< HEAD\n",
            "nonce: aaa111\n",
            "\n",
            "Ours body.\n",
            "=======\n",
            "nonce: bbb222\n",
            "\n",
            "Theirs body.\n",
            ">>>>>>> feature\n",
        );
        let sides = split_conflict_sides(text).unwrap();
        assert_eq!(
            sides.ours,
            "---\nid: p-01J0000000000000000000000\ntype: person\nname: Ada Example\n---\nnonce: aaa111\n\nOurs body.\n"
        );
        assert_eq!(
            sides.theirs,
            "---\nid: p-01J0000000000000000000000\ntype: person\nname: Ada Example\n---\nnonce: bbb222\n\nTheirs body.\n"
        );
        assert_eq!(sides.ours_label, "HEAD");
        assert_eq!(sides.theirs_label, "feature");
    }

    #[test]
    fn multiple_hunks_header_and_body() {
        let text = concat!(
            "---\n",
            "<<<<<<< HEAD\n",
            "key_id: aaa\n",
            "=======\n",
            "key_id: bbb\n",
            ">>>>>>> branch\n",
            "type: person\n",
            "name: Ada Example\n",
            "---\n",
            "<<<<<<< HEAD\n",
            "Body ours.\n",
            "=======\n",
            "Body theirs.\n",
            ">>>>>>> branch\n",
        );
        let sides = split_conflict_sides(text).unwrap();
        assert_eq!(
            sides.ours,
            "---\nkey_id: aaa\ntype: person\nname: Ada Example\n---\nBody ours.\n"
        );
        assert_eq!(
            sides.theirs,
            "---\nkey_id: bbb\ntype: person\nname: Ada Example\n---\nBody theirs.\n"
        );
    }

    #[test]
    fn common_suffix_after_hunk_goes_to_both() {
        let text = "<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch\ncommon suffix\n";
        let sides = split_conflict_sides(text).unwrap();
        assert_eq!(sides.ours, "ours\ncommon suffix\n");
        assert_eq!(sides.theirs, "theirs\ncommon suffix\n");
    }

    #[test]
    fn diff3_base_block_is_ignored() {
        let text = concat!(
            "<<<<<<< HEAD\n",
            "ours\n",
            "||||||| base\n",
            "base content\n",
            "=======\n",
            "theirs\n",
            ">>>>>>> branch\n",
        );
        let sides = split_conflict_sides(text).unwrap();
        assert_eq!(sides.ours, "ours\n");
        assert_eq!(sides.theirs, "theirs\n");
    }

    #[test]
    fn crlf_preserved_byte_for_byte() {
        let text = "common\r\n<<<<<<< HEAD\r\nours\r\n=======\r\ntheirs\r\n>>>>>>> branch\r\n";
        let sides = split_conflict_sides(text).unwrap();
        assert_eq!(sides.ours, "common\r\nours\r\n");
        assert_eq!(sides.theirs, "common\r\ntheirs\r\n");
    }

    #[test]
    fn no_trailing_newline_preserved() {
        let text = "<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch";
        let sides = split_conflict_sides(text).unwrap();
        assert_eq!(sides.ours, "ours");
        assert_eq!(sides.theirs, "theirs");
    }

    #[test]
    fn labels_are_extracted() {
        let text = "<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> feature/x\n";
        let sides = split_conflict_sides(text).unwrap();
        assert_eq!(sides.ours_label, "HEAD");
        assert_eq!(sides.theirs_label, "feature/x");
    }

    #[test]
    fn bare_start_marker_has_empty_label() {
        let text = "<<<<<<<\nours\n=======\ntheirs\n>>>>>>>\n";
        let sides = split_conflict_sides(text).unwrap();
        assert_eq!(sides.ours_label, "");
        assert_eq!(sides.theirs_label, "");
        assert_eq!(sides.ours, "ours\n");
        assert_eq!(sides.theirs, "theirs\n");
    }

    #[test]
    fn setext_equals_line_outside_hunk_is_not_a_marker() {
        let text = "Title\n=======\n\nSome text.\n";
        assert_eq!(
            split_conflict_sides(text),
            Err(ConflictSplitError::NoMarkers)
        );
    }

    #[test]
    fn error_no_markers() {
        let text = "just some text\nno markers here\n";
        assert_eq!(
            split_conflict_sides(text),
            Err(ConflictSplitError::NoMarkers)
        );
        assert_eq!(split_conflict_sides(""), Err(ConflictSplitError::NoMarkers));
    }

    #[test]
    fn error_unterminated_hunk() {
        assert!(matches!(
            split_conflict_sides("<<<<<<< HEAD\nours\n"),
            Err(ConflictSplitError::Malformed(_))
        ));
        assert!(matches!(
            split_conflict_sides("<<<<<<< HEAD\nours\n=======\ntheirs\n"),
            Err(ConflictSplitError::Malformed(_))
        ));
    }

    #[test]
    fn error_separator_without_start() {
        let text = "<<<<<<< HEAD\nours\n=======\ntheirs\n=======\nmore\n>>>>>>> branch\n";
        assert!(matches!(
            split_conflict_sides(text),
            Err(ConflictSplitError::Malformed(_))
        ));
    }

    #[test]
    fn error_nested_start() {
        let text = "<<<<<<< HEAD\n<<<<<<< HEAD\n=======\n>>>>>>> branch\n";
        assert!(matches!(
            split_conflict_sides(text),
            Err(ConflictSplitError::Malformed(_))
        ));
    }

    #[test]
    fn error_end_without_start() {
        assert!(matches!(
            split_conflict_sides("some text\n>>>>>>> branch\n"),
            Err(ConflictSplitError::Malformed(_))
        ));
    }

    #[test]
    fn error_marker_size_9() {
        let text = "<<<<<<<<< HEAD\nours\n=========\ntheirs\n>>>>>>>>> branch\n";
        assert_eq!(
            split_conflict_sides(text),
            Err(ConflictSplitError::UnsupportedMarkerSize)
        );
    }

    #[test]
    fn error_21_hunks() {
        let mut text = String::new();
        for i in 0..21 {
            text.push_str(&format!(
                "<<<<<<< HEAD\nours {i}\n=======\ntheirs {i}\n>>>>>>> branch\n"
            ));
        }
        assert_eq!(
            split_conflict_sides(&text),
            Err(ConflictSplitError::TooManyHunks)
        );
    }

    #[test]
    fn twenty_hunks_is_ok() {
        let mut text = String::new();
        for i in 0..20 {
            text.push_str(&format!(
                "<<<<<<< HEAD\nours {i}\n=======\ntheirs {i}\n>>>>>>> branch\n"
            ));
        }
        let sides = split_conflict_sides(&text).unwrap();
        assert!(sides.ours.contains("ours 19\n"));
        assert!(sides.theirs.contains("theirs 0\n"));
    }

    #[test]
    fn error_messages_carry_no_content() {
        // Every variant's Display is static text.
        let errs = [
            ConflictSplitError::NoMarkers,
            ConflictSplitError::Malformed("nested start marker"),
            ConflictSplitError::TooManyHunks,
            ConflictSplitError::UnsupportedMarkerSize,
        ];
        for e in errs {
            let msg = e.to_string();
            assert!(!msg.contains("secret"), "leak in: {msg}");
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn git_round_trip_sides_equal_committed_files() {
        fn git(root: &std::path::Path, args: &[&str]) -> std::process::Output {
            std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .output()
                .expect("git must be installed for this test")
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q", "-b", "main"]);
        git(root, &["config", "user.email", "test@example.com"]);
        git(root, &["config", "user.name", "Test"]);
        git(root, &["config", "commit.gpgsign", "false"]);

        let header = "---\nid: p-01J0000000000000000000000\ntype: person\nname: Ada Example\n---\n";
        // Base commit; both branches then change the SAME lines (nonce and
        // body) differently, so every differing line conflicts and each
        // reconstructed side equals the corresponding committed file.
        let base = format!("{header}nonce: aaa111\n\nBase body.\n");
        std::fs::write(root.join("a.md"), &base).unwrap();
        git(root, &["add", "a.md"]);
        git(root, &["commit", "-q", "-m", "base"]);

        git(root, &["checkout", "-q", "-b", "feature"]);
        let feature_v = format!("{header}nonce: bbb222\n\nFeature body.\n");
        std::fs::write(root.join("a.md"), &feature_v).unwrap();
        git(root, &["commit", "-q", "-am", "feature version"]);

        git(root, &["checkout", "-q", "main"]);
        let main_v = format!("{header}nonce: ccc333\n\nMain body.\n");
        std::fs::write(root.join("a.md"), &main_v).unwrap();
        git(root, &["commit", "-q", "-am", "main version"]);

        let merge = git(root, &["merge", "--no-edit", "feature"]);
        assert!(!merge.status.success(), "expected a conflicted merge");

        let conflicted = std::fs::read_to_string(root.join("a.md")).unwrap();
        assert!(has_conflict_markers(&conflicted));
        let sides = split_conflict_sides(&conflicted).unwrap();

        let main_committed = String::from_utf8(git(root, &["show", "main:a.md"]).stdout).unwrap();
        let feature_committed =
            String::from_utf8(git(root, &["show", "feature:a.md"]).stdout).unwrap();
        assert_eq!(sides.ours, main_committed);
        assert_eq!(sides.theirs, feature_committed);
        assert_eq!(sides.ours_label, "HEAD");
        assert_eq!(sides.theirs_label, "feature");
    }

    #[test]
    fn never_panics_on_truncations() {
        let text = "---\nid: x\n---\n<<<<<<< HEAD\nours line 1\nours line 2\n=======\ntheirs line\n>>>>>>> feature\ntrailing\n";
        // Every char-boundary prefix must not panic.
        for (i, _) in text.char_indices() {
            let _ = split_conflict_sides(&text[..i]);
        }
        let _ = split_conflict_sides(text);
        // A few deterministic line shuffles must not panic either.
        let lines: Vec<&str> = text.split('\n').collect();
        let mut rev = lines.clone();
        rev.reverse();
        let _ = split_conflict_sides(&rev.join("\n"));
        let mut rot = lines.clone();
        rot.rotate_left(3);
        let _ = split_conflict_sides(&rot.join("\n"));
    }
}
