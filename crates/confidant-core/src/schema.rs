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
                "required": ["error", "check", "find", "allowlist", "write", "context", "doctor", "help"],
                "properties": {
                    "error": {"$ref": "#/$defs/error"},
                    "check": {"$ref": "#/$defs/checkReport"},
                    "find": {"$ref": "#/$defs/findResponse"},
                    "allowlist": {"$ref": "#/$defs/allowlistResponse"},
                    "write": {"$ref": "#/$defs/writeResponse"},
                    "context": {"$ref": "#/$defs/contextBundle"},
                    "doctor": {"$ref": "#/$defs/doctorReport"},
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
                        "description": "Dry-run only: the logical change (ledger lines / plaintext). Never ciphertext.",
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
                "description": "Everything the vault knows about one person. PII fields (name/profile/bodies) are shown only for records in the section-12 cleared set — exactly like find; uncleared notes/interactions are omitted entirely, never nulled. --exclude-private strips PII regardless; ledger facts are kept. The `packs[\"personal@0.1\"]` entry (core: context::personal) carries the personal pack's declared fields (birthday, dates, relationship, location, emails, phones, links, tags, …) plus cadence_days, snooze_until, last_touch, days_since_touch, overdue and recent_touches. --exclude-private removes the PII fields by name; title, company, cadence_days and snooze_until stay. For a person outside the cleared set (no-ai) the declared fields are denied by default: only snooze_until and the derived cadence/touch metadata (cadence_days, last_touch, days_since_touch, overdue, recent_touches) remain.",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "person", "notes", "interactions", "coaching", "packs", "aliases"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "person": {
                        "type": "object",
                        "required": ["id", "no_ai"],
                        "properties": {
                            "id": {"type": "string"},
                            "name": {"type": ["string", "null"]},
                            "no_ai": {"type": "boolean"},
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
                    "coaching": {
                        "type": ["object", "null"],
                        "properties": {
                            "sessions_remaining": {"type": "integer"},
                            "icf_hours": {"type": "number"},
                            "recent_sessions": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["date"],
                                    "properties": {
                                        "date": {"type": "string"},
                                        "duration_minutes": {"type": ["integer", "null"]},
                                        "tag": {"type": ["string", "null"], "enum": ["paid", "pps", "comp", null]}
                                    }
                                }
                            }
                        }
                    },
                    "packs": {
                        "type": "object",
                        "description": "Pack state grouped by pack name (\"coaching@0.1\" today). Each pack decides its own view shape. The legacy \"coaching\" field duplicates this map's coaching entry."
                    },
                    "scope": {"type": "array", "description": "Resolved pack scope that filtered the bundle (issue #178); all enabled packs when unscoped.", "items": {"type": "string"}},
                    "aliases": {"type": "array", "items": {"type": "string"}, "description": "Opaque hmac:<hex> values."}
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
            "doctor",
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
            "doctor" => "doctorReport",
            "help" => "helpJson",
            _ => shape,
        }
    }
}
