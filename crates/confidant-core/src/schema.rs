//! Hand-authored JSON Schema for the `confidant` agent contract (`schema`).
//!
//! Covers every `--json` output shape an agent may consume. Versioned
//! independently of the vault spec via `schema_version` on each envelope.
//! Kept hand-authored (not derived) so the contract stays stable even as
//! internal Rust types churn.

use serde_json::{json, Value};

/// The full contract schema document.
pub fn contract_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/hirefrank/confidant/schema/contract-1.json",
        "title": "Confidant agent contract",
        "description": "Machine-readable shapes for every `confidant --json` output. Callers classify by `code`, never by message text.",
        "type": "object",
        "required": ["schema_version", "shapes"],
        "properties": {
            "schema_version": {"type": "string", "const": "1"},
            "shapes": {
                "type": "object",
                "required": ["error", "check", "find", "allowlist", "write", "context", "roster", "doctor", "sync", "help"],
                "properties": {
                    "error": {"$ref": "#/$defs/error"},
                    "check": {"$ref": "#/$defs/checkReport"},
                    "find": {"$ref": "#/$defs/findResponse"},
                    "allowlist": {"$ref": "#/$defs/allowlistResponse"},
                    "write": {"$ref": "#/$defs/writeResponse"},
                    "context": {"$ref": "#/$defs/contextBundle"},
                    "roster": {"$ref": "#/$defs/rosterResponse"},
                    "doctor": {"$ref": "#/$defs/doctorReport"},
                    "sync": {"$ref": "#/$defs/syncReport"},
                    "help": {"$ref": "#/$defs/helpJson"}
                }
            }
        },
        "$defs": {
            "error": {
                "title": "Error envelope",
                "description": "Every failure prints this on stdout in `--json` mode. `error.code` is stable; `error.message` is human-only.",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "error"],
                "properties": {
                    "ok": {"type": "boolean", "const": false},
                    "schema_version": {"type": "string"},
                    "vault": {"type": ["string", "null"]},
                    "error": {
                        "type": "object",
                        "required": ["code", "message"],
                        "properties": {
                            "code": {
                                "type": "string",
                                "description": "Stable machine code, e.g. E_VAULT_NOT_FOUND, E_IDEMPOTENCY_CONFLICT, E_CONFLICT, E_NOT_FOUND, usage_error."
                            },
                            "message": {"type": "string"},
                            "file": {"type": ["string", "null"]},
                            "line": {"type": ["integer", "null"]},
                            "fix": {"type": ["string", "null"]}
                        }
                    }
                }
            },
            "entityView": {
                "title": "context entity",
                "description": "The context target: a person or an org (#813). `no_ai` is a boolean on the agent path; the operator-only path reports the tri-state string instead.",
                "type": "object",
                "required": ["id", "kind", "no_ai"],
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"type": "string", "enum": ["person", "org"]},
                    "name": {"type": ["string", "null"]},
                    "no_ai": {
                        "type": ["boolean", "string"],
                        "description": "Agent path: boolean. Operator path: the tri-state string (`true`, `notes`, or `false`)."
                    },
                    "profile": {"type": ["string", "null"]}
                }
            },
            "edgeView": {
                "title": "context edge",
                "description": "One edge from the target's point of view (#813). Opaque ids, kind, and dates are kept under --exclude-private; endpoint names are stripped. An edge appears only when both endpoints are in the section-12 cleared set and the edge itself is not no-ai: true. The operator path also carries the edge's own no_ai badge.",
                "type": "object",
                "required": ["id", "kind", "direction", "other"],
                "properties": {
                    "id": {"type": "string"},
                    "kind": {"type": "string"},
                    "direction": {"type": "string", "enum": ["out", "in", "none"]},
                    "other": {
                        "type": "object",
                        "required": ["id", "kind"],
                        "properties": {
                            "id": {"type": "string"},
                            "kind": {"type": "string", "enum": ["person", "org"]},
                            "name": {"type": ["string", "null"]},
                            "no_ai": {
                                "type": ["string", "boolean"],
                                "description": "Operator path only: the other endpoint's tri-state no-ai badge."
                            }
                        }
                    },
                    "since": {"type": ["string", "null"]},
                    "until": {"type": ["string", "null"]},
                    "no_ai": {
                        "type": "string",
                        "enum": ["true", "false"],
                        "description": "Operator path only: the edge's own no-ai badge. Edges have no notes mode."
                    }
                }
            },
            "checkReport": {
                "title": "check --json",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "spec", "summary", "findings"],
                "properties": {
                    "ok": {"type": "boolean"},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "spec": {"type": "string"},
                    "summary": {
                        "type": "object",
                        "required": ["records", "ledger_entries", "errors", "warnings"],
                        "properties": {
                            "records": {"type": "integer"},
                            "ledger_entries": {"type": "integer"},
                            "errors": {"type": "integer"},
                            "warnings": {"type": "integer"}
                        }
                    },
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["code", "severity", "message"],
                            "properties": {
                                "code": {"type": "string", "description": "Stable E_* code."},
                                "severity": {"type": "string", "enum": ["error", "warning"]},
                                "message": {"type": "string"},
                                "file": {"type": ["string", "null"]},
                                "line": {"type": ["integer", "null"]},
                                "id": {"type": ["string", "null"]},
                                "fix": {"type": ["string", "null"]}
                            }
                        }
                    }
                }
            },
            "findResponse": {
                "title": "find --json",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "query", "matches", "findings"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "query": {"type": "string"},
                    "matches": {
                        "type": "array",
                        "description": "Allowlisted hits only; no-ai records never appear.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": ["string", "null"]},
                                "path": {"type": "string"},
                                "line": {"type": ["integer", "null"]},
                                "excerpt": {"type": "string"}
                            }
                        }
                    },
                    "findings": {"type": "array", "description": "Load findings; raw record text never included."},
                    "scope": {"type": "array", "description": "Resolved pack scope that filtered the results (issue #178); all enabled packs when unscoped.", "items": {"type": "string"}}
                }
            },
            "allowlistResponse": {
                "title": "allowlist --json",
                "description": "Section-12 cleared set for index-time corpus exclusion (issue #38). Opaque paths and line numbers only, never content; no-ai records never appear. The query-time allowlist stays the authority. With --packs, only in-scope items are listed and each carries its owning packs (issue #178).",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "cleared_files", "cleared_ledger_lines"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "scope": {"type": "array", "description": "Resolved pack scope that filtered the listing (issue #178); all enabled packs when unscoped.", "items": {"type": "string"}},
                    "owning_packs": {
                        "type": "object",
                        "description": "Owning pack per cleared file: [] = unattributed (only listed unscoped), [\"core\"] = core-owned.",
                        "additionalProperties": {"type": "array", "items": {"type": "string"}}
                    },
                    "cleared_files": {
                        "type": "array",
                        "description": "Vault-relative paths of cleared record files, sorted.",
                        "items": {"type": "string"}
                    },
                    "cleared_ledger_lines": {
                        "type": "array",
                        "description": "Cleared canonical ledger lines, sorted by file then line.",
                        "items": {
                            "type": "object",
                            "required": ["file", "line"],
                            "properties": {
                                "file": {"type": "string"},
                                "line": {"type": "integer"},
                                "owning_packs": {"type": "array", "description": "Owning packs of this line: [] = unattributed (only listed unscoped), [\"core\"] = core-owned.", "items": {"type": "string"}}
                            }
                        }
                    }
                }
            },
            "writeResponse": {
                "title": "log session / import / note add --json",
                "description": "One commit per write. Commit messages carry only opaque IDs, verbs, hashes. --request-id must be unguessable (at least 22 characters; use a ULID or UUIDv4): the Request-Hash trailer HMACs the canonical request with the raw id as key, and trailers are permanent, so a guessable id is an offline guessing oracle even after shredding.",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "command"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "command": {"type": "string", "enum": ["log-session", "import", "note-add", "record-add", "record-edit"]},
                    "dry_run": {"type": "boolean"},
                    "idempotent": {"type": "boolean"},
                    "unchanged": {"type": "boolean", "description": "The write would not change any file (for example re-saving a record with identical content). No commit is reported with it; exit status is success."},
                    "commit": {"type": ["string", "null"], "description": "Full commit SHA; null on dry-run."},
                    "files": {"type": "array", "items": {"type": "string"}},
                    "lines": {"type": "array", "items": {"type": "string"}, "description": "Ledger lines appended (log/import). Opaque IDs only."},
                    "id": {"type": ["string", "null"], "description": "New record id (note-add)."},
                    "path": {"type": ["string", "null"], "description": "New record path (note-add)."},
                    "rekeyed": {
                        "type": ["object", "null"],
                        "description": "record-edit only: the record moved to another client's key. Absent when it did not.",
                        "properties": {
                            "from": {"type": "string", "description": "Opaque client id that held the record."},
                            "to": {"type": "string", "description": "Opaque client id that holds it now."}
                        }
                    },
                    "changes": {
                        "type": "array",
                        "description": "Dry-run only: the logical change (ledger lines / plaintext record text).",
                        "items": {
                            "type": "object",
                            "required": ["path", "action", "content"],
                            "properties": {
                                "path": {"type": "string"},
                                "action": {"type": "string", "enum": ["append", "write"]},
                                "content": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "contextBundle": {
                "title": "context --json",
                "description": "Everything the vault knows about one entity: a person or an org (#813). `entity` is the canonical target view; `person` is a deprecated person-only alias, present only when the target is a person. PII fields (name/profile/bodies/edge endpoint names) are shown only for records in the section-12 cleared set — exactly like find; uncleared notes/interactions/edges are omitted entirely, never nulled. An edge is visible only when both endpoints are cleared and the edge itself is not no-ai: true, so a no-ai endpoint or no-ai edge omits the edge from the other endpoint's bundle with no count or hint; an operator bundle badges it instead. --exclude-private strips PII regardless; ledger facts and opaque edge ids/kinds/dates are kept. The `packs[\"personal@0.2\"]` entry (core: context::personal) carries the personal pack's declared fields (birthday, dates, relationship, location, emails, phones, links, tags, …) plus cadence_days, cadence_never, snooze_until, last_touch, days_since_touch, overdue and recent_touches. cadence_never is true only when the declared cadence is the literal `never` (and is omitted otherwise), so it distinguishes a deliberate never-nudge from no cadence set: both omit cadence_days. --exclude-private removes the PII fields by name; title, company, cadence_days and snooze_until stay. For a person outside the cleared set (no-ai) the declared fields are denied by default: only snooze_until and the derived cadence/touch metadata (cadence_days, cadence_never, last_touch, days_since_touch, overdue, recent_touches) remain. An org bundle has empty `touchpoints`, `aliases`, and `packs`; its notes/interactions are those linked by `org:`.",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "entity", "notes", "interactions", "edges", "packs", "aliases"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "entity": {"$ref": "#/$defs/entityView"},
                    "person": {
                        "type": "object",
                        "description": "Deprecated person-only alias, present only for a person target. New readers use `entity`.",
                        "required": ["id", "no_ai"],
                        "properties": {
                            "id": {"type": "string"},
                            "name": {"type": ["string", "null"]},
                            "no_ai": {
                                "type": ["boolean", "string"],
                                "description": "Agent path: boolean. Operator path: the tri-state string (`true`, `notes`, or `false`)."
                            },
                            "profile": {"type": ["string", "null"]}
                        }
                    },
                    "notes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id"],
                            "properties": {
                                "id": {"type": "string"},
                                "date": {"type": ["string", "null"]},
                                "body": {"type": ["string", "null"]}
                            }
                        }
                    },
                    "interactions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id"],
                            "properties": {
                                "id": {"type": "string"},
                                "date": {"type": ["string", "null"]},
                                "title": {"type": ["string", "null"]},
                                "body": {"type": ["string", "null"]}
                            }
                        }
                    },
                    "edges": {
                        "type": "array",
                        "description": "Edges whose endpoint is this entity, cleared-set-gated and merge-canonicalized (#813). Empty when the target has none or either endpoint is not cleared.",
                        "items": {"$ref": "#/$defs/edgeView"}
                    },
                    "packs": {
                        "type": "object",
                        "description": "Pack state grouped by pack name (the built-in personal pack is \"personal@0.2\"; an enabled external pack may add its own view). Each pack decides its own view shape. Empty for an org target."
                    },
                    "scope": {"type": "array", "description": "Resolved pack scope that filtered the bundle (issue #178); all enabled packs when unscoped.", "items": {"type": "string"}},
                    "aliases": {"type": "array", "items": {"type": "string"}, "description": "Contact values from the person's front-matter emails, phones, and handles (empty under --exclude-private and for uncleared records)."}
                }
            },
            "rosterResponse": {
                "title": "record list --json",
                "description": "Operator-only roster (#558, #813). `record list` is never exposed over MCP. `kind` is the requested filter; the default is `all`, which covers the three identity kinds person, org, and deal (deals are listable but never edge endpoints). `kinds` lists the kinds included by this call. Without --for-operator entries are the section-12 cleared set; with it, records hidden only by their own no-ai are added and every entry carries the tri-state no_ai string the #559 ruling specifies.",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "kind", "kinds", "for_operator", "records", "scope"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "kind": {"type": "string", "enum": ["all", "person", "org", "deal"]},
                    "kinds": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["person", "org", "deal"]}
                    },
                    "for_operator": {"type": "boolean"},
                    "records": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/rosterEntry"}
                    },
                    "scope": {"type": "array", "items": {"type": "string"}}
                }
            },
            "rosterEntry": {
                "title": "record list entry",
                "type": "object",
                "required": ["id", "name", "no_ai", "kind"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string", "description": "Display name, falling back to the opaque id."},
                    "no_ai": {"type": "string", "enum": ["true", "notes", "false"]},
                    "kind": {"type": "string", "enum": ["person", "org", "deal"]}
                }
            },
            "doctorReport": {
                "title": "doctor --json",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "checks"],
                "properties": {
                    "ok": {"type": "boolean"},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "checks": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id", "status", "message"],
                            "properties": {
                                "id": {"type": "string"},
                                "status": {"type": "string", "enum": ["ok", "warning", "error", "unknown"]},
                                "message": {"type": "string"}
                            }
                        }
                    }
                }
            },
            "syncReport": {
                "title": "sync --json",
                "description": "Ahead/behind counts after the fetch (or from the last fetch with --dry-run). Only a vault with a remote and upstream reaches this shape; otherwise the error envelope carries E_NO_REMOTE or E_NOT_FAST_FORWARD.",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "remote", "branch", "upstream", "ahead", "behind", "fetched", "dry_run", "action", "applied"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "remote": {"type": "string"},
                    "branch": {"type": "string"},
                    "upstream": {"type": "string"},
                    "ahead": {"type": "integer", "minimum": 0},
                    "behind": {"type": "integer", "minimum": 0},
                    "fetched": {"type": "boolean", "description": "False when --dry-run skipped the fetch."},
                    "dry_run": {"type": "boolean"},
                    "action": {"type": "string", "enum": ["none", "pull", "push"]},
                    "applied": {"type": "boolean", "description": "True only when a confirmed pull or push ran."}
                }
            },
            "helpJson": {
                "title": "help --json",
                "description": "Generated from the live clap definitions, so it cannot drift from the CLI.",
                "type": "object",
                "required": ["ok", "schema_version", "commands"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "commands": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name"],
                            "properties": {
                                "name": {"type": "string"},
                                "about": {"type": ["string", "null"]},
                                "args": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["id"],
                                        "properties": {
                                            "id": {"type": "string"},
                                            "help": {"type": ["string", "null"]},
                                            "required": {"type": "boolean"}
                                        }
                                    }
                                },
                                "subcommands": {"type": "array", "items": {"type": "string"}}
                            }
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #813: the context shape is an entity bundle with edges; `person` is
    /// the deprecated person-only alias and is no longer required.
    #[test]
    fn context_schema_has_entity_and_edges() {
        let s = contract_schema();
        let context = &s["$defs"]["contextBundle"];
        let required: Vec<&str> = context["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert!(required.contains(&"entity"), "{required:?}");
        assert!(required.contains(&"edges"), "{required:?}");
        assert!(!required.contains(&"person"), "{required:?}");
        assert!(context["properties"]["person"].is_object());
        assert_eq!(
            context["properties"]["entity"]["$ref"],
            "#/$defs/entityView"
        );
        assert_eq!(
            context["properties"]["edges"]["items"]["$ref"],
            "#/$defs/edgeView"
        );
        assert!(s["$defs"]["entityView"]["properties"]["kind"]["enum"].is_array());
        assert!(s["$defs"]["edgeView"]["properties"]["direction"]["enum"].is_array());
        assert!(s["$defs"]["edgeView"]["properties"]["no_ai"].is_object());
        assert_eq!(s["properties"]["schema_version"]["const"], "1");
    }

    /// #813: the roster shape documents the `all` default and the three
    /// identity kinds; `record list` stays an operator-only command.
    #[test]
    fn roster_schema_has_all_default_and_identity_kinds() {
        let s = contract_schema();
        assert_eq!(
            s["properties"]["shapes"]["properties"]["roster"]["$ref"],
            "#/$defs/rosterResponse"
        );
        let roster = &s["$defs"]["rosterResponse"];
        let required: Vec<&str> = roster["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        for field in ["kind", "kinds", "records", "for_operator"] {
            assert!(required.contains(&field), "{field}: {required:?}");
        }
        assert!(roster["properties"]["kind"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "all"));
        assert_eq!(
            s["$defs"]["rosterEntry"]["properties"]["kind"]["enum"],
            serde_json::json!(["person", "org", "deal"])
        );
        assert_eq!(s["properties"]["schema_version"]["const"], "1");
    }

    #[test]
    fn schema_is_well_formed() {
        let s = contract_schema();
        assert_eq!(s["properties"]["schema_version"]["const"], "1");
        for shape in [
            "error",
            "check",
            "find",
            "allowlist",
            "write",
            "context",
            "roster",
            "doctor",
            "sync",
            "help",
        ] {
            assert!(
                s["properties"]["shapes"]["properties"][shape].is_object(),
                "shape {shape} missing"
            );
            assert!(
                s["$defs"][shape_name(shape)].is_object(),
                "def for {shape} missing"
            );
        }
    }

    fn shape_name(shape: &str) -> &str {
        match shape {
            "check" => "checkReport",
            "find" => "findResponse",
            "allowlist" => "allowlistResponse",
            "write" => "writeResponse",
            "context" => "contextBundle",
            "roster" => "rosterResponse",
            "doctor" => "doctorReport",
            "sync" => "syncReport",
            "help" => "helpJson",
            _ => shape,
        }
    }
}
