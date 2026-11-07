//! `bench-gen`: write a fake vault for search benchmarks.

use std::path::Path;
use std::process::ExitCode;

pub(crate) fn cmd_bench_gen(
    json: bool,
    dir: &Path,
    people: usize,
    notes: usize,
    cjk: bool,
    touch: bool,
) -> anyhow::Result<ExitCode> {
    let (unique, common) =
        confidant_core::bench::generate_realistic_vault(dir, people, notes, cjk, touch)?;
    if json {
        crate::print_json(&crate::ok_envelope(
            Some(dir),
            serde_json::json!({
                "people": people,
                "notes_per_person": notes,
                "unique_token": unique,
                "common_token": common,
            }),
        ))?;
    } else {
        println!("wrote {people} people × {notes} notes at {}", dir.display());
        println!("unique token: {unique}");
        println!("common token: {common}");
    }
    Ok(ExitCode::SUCCESS)
}
