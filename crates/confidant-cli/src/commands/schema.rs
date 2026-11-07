//! `schema`: the agent-contract JSON Schema.

use std::path::Path;
use std::process::ExitCode;

use crate::{ok_envelope, print_json, resolve_cli_scope, Cli};
use confidant_core::load_vault;
use confidant_core::schema::{contract_schema, record_types_json};

pub(crate) fn cmd_schema(cli: &Cli, vault: Option<&Path>) -> anyhow::Result<ExitCode> {
    let mut schema = contract_schema();
    if let Some(root) = vault {
        let loaded = load_vault(root).map_err(anyhow::Error::new)?;
        let (scope, _) =
            resolve_cli_scope(&loaded, cli.packs.as_deref()).map_err(anyhow::Error::new)?;
        schema["record_types"] = record_types_json(Some(&loaded), Some(&scope));
    }
    if cli.json {
        print_json(&ok_envelope(vault, serde_json::json!({"contract": schema})))?;
    } else {
        println!("{}", serde_json::to_string_pretty(&schema)?);
    }
    Ok(ExitCode::SUCCESS)
}
