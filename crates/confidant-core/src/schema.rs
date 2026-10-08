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
                "required": ["error", "check", "find", "write", "context", "doctor", "help"],
                "properties": {
                    "error": {"$ref": "#/$defs/error"},
                    "check": {"$ref": "#/$defs/checkReport"},
                    "find": {"$ref": "#/$defs/findResponse"},
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
                "description": "Every failure prints this on stderr. `code` is stable; `message` is human-only.",
                "type": "object",
                "required": ["ok", "code", "message"],
                "properties": {
                    "ok": {"type": "boolean", "const": false},
                    "code": {
                        "type": "string",
                        "description": "Stable machine code, e.g. E_VAULT_NOT_FOUND, E_IDEMPOTENCY_CONFLICT, E_CONFLICT, E_NOT_FOUND, usage_error."
                    },
                    "message": {"type": "string"},
                    "file": {"type": ["string", "null"]},
                    "line": {"type": ["integer", "null"]},
                    "fix": {"type": ["string", "null"]},
                    "vault": {"type": ["string", "null"]}
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
                    "findings": {"type": "array", "description": "Load findings; raw record text never included."}
                }
            },
            "writeResponse": {
                "title": "log session / import / note add --json",
                "description": "One commit per write. Commit messages carry only opaque IDs, verbs, hashes. --request-id must carry at least 128 bits of entropy (at least 22 characters; ULID/UUIDv4 recommended): the Request-Hash trailer HMACs the canonical request with the raw id as key, and trailers are permanent, so a guessable id is an offline guessing oracle even after shredding.",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "command"],
                "properties": {
                    "ok": {"type": "boolean", "const": true},
                    "schema_version": {"type": "string"},
                    "vault": {"type": "string"},
                    "command": {"type": "string", "enum": ["log-session", "import", "note-add"]},
                    "dry_run": {"type": "boolean"},
                    "idempotent": {"type": "boolean"},
                    "commit": {"type": ["string", "null"], "description": "Full commit SHA; null on dry-run."},
                    "files": {"type": "array", "items": {"type": "string"}},
                    "lines": {"type": "array", "items": {"type": "string"}, "description": "Ledger lines appended (log/import). Opaque IDs only."},
                    "id": {"type": ["string", "null"], "description": "New record id (note-add)."},
                    "path": {"type": ["string", "null"], "description": "New record path (note-add)."},
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
                "description": "Everything the vault knows about one person. PII fields (name/profile/bodies) are shown only for records in the section-12 cleared set — exactly like find; uncleared notes/interactions are omitted entirely, never nulled. --exclude-private strips PII regardless; ledger facts are kept.",
                "type": "object",
                "required": ["ok", "schema_version", "vault", "person", "notes", "interactions", "coaching", "aliases"],
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
            "error", "check", "find", "write", "context", "doctor", "help",
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
            "write" => "writeResponse",
            "context" => "contextBundle",
            "doctor" => "doctorReport",
            "help" => "helpJson",
            _ => shape,
        }
    }
}
