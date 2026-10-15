//! Process execution boundary for invoking the `confidant` CLI.
//!
//! `ProcessRunner` invokes `std::process::Command` directly (never a shell),
//! always passes `--json` and `--no-input`, forwards `--vault` when provided,
//! and drops `stderr` so nothing from `stderr` is ever stored or displayed.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context as _, Result};

/// Raw stdout and exit status from one `confidant` CLI invocation.
///
/// `stderr` is intentionally omitted: the TUI reads only `stdout`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
}

/// Abstraction over running `confidant` with CLI arguments.
pub trait Runner {
    fn run(&self, args: &[&str]) -> Result<RawOutput>;

    /// Run an external program (not the `confidant` binary): no `--json`,
    /// `--no-input`, or `--vault` is injected. Used for skill `--cleanup`
    /// scripts, which are plain programs with their own flags.
    fn run_program(&self, program: &str, args: &[&str]) -> Result<RawOutput>;
}

/// Real child-process runner that executes the resolved `confidant` binary.
#[derive(Clone, Debug)]
pub struct ProcessRunner {
    bin: PathBuf,
    vault: Option<PathBuf>,
    envs: Vec<(String, String)>,
}

impl ProcessRunner {
    /// Create a runner for `bin` and optional `--vault` override.
    pub fn new(bin: PathBuf, vault: Option<PathBuf>) -> Self {
        Self {
            bin,
            vault,
            envs: Vec::new(),
        }
    }

    /// Add an environment variable override for the child process.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }

    /// Resolve the `confidant` binary path from an explicit CLI flag,
    /// `CONFIDANT_BIN`, or `"confidant"` on `PATH`.
    pub fn resolve_bin(cli_bin: Option<PathBuf>) -> PathBuf {
        if let Some(bin) = cli_bin {
            return bin;
        }
        if let Some(env_bin) = std::env::var_os("CONFIDANT_BIN") {
            if !env_bin.is_empty() {
                return PathBuf::from(env_bin);
            }
        }
        PathBuf::from("confidant")
    }

    /// The resolved `confidant` binary path.
    pub fn bin(&self) -> &PathBuf {
        &self.bin
    }

    /// The configured `--vault` override, if any.
    pub fn vault(&self) -> Option<&PathBuf> {
        self.vault.as_ref()
    }
}

impl Runner for ProcessRunner {
    fn run(&self, args: &[&str]) -> Result<RawOutput> {
        let mut cmd = Command::new(&self.bin);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }

        if !args.contains(&"--json") {
            cmd.arg("--json");
        }
        if !args.contains(&"--no-input") {
            cmd.arg("--no-input");
        }
        if let Some(vault) = &self.vault {
            if !args.contains(&"--vault") {
                cmd.arg("--vault").arg(vault);
            }
        }
        cmd.args(args);

        let output = cmd
            .output()
            .with_context(|| format!("failed to execute {}", self.bin.display()))?;
        let status = output.status.code().unwrap_or(1);
        Ok(RawOutput {
            status,
            stdout: output.stdout,
        })
    }

    fn run_program(&self, program: &str, args: &[&str]) -> Result<RawOutput> {
        let mut cmd = Command::new(program);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }
        cmd.args(args);

        let output = cmd
            .output()
            .with_context(|| format!("failed to execute {program}"))?;
        let status = output.status.code().unwrap_or(1);
        Ok(RawOutput {
            status,
            stdout: output.stdout,
        })
    }
}

/// In-memory fake runner for deterministic unit and snapshot tests.
#[derive(Clone, Debug, Default)]
pub struct FakeRunner {
    queue: RefCell<VecDeque<RawOutput>>,
    by_subcommand: HashMap<String, RawOutput>,
    by_program: HashMap<String, RawOutput>,
    fallback: Option<RawOutput>,
    calls: RefCell<Vec<Vec<String>>>,
    program_calls: RefCell<Vec<(String, Vec<String>)>>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a `FakeRunner` that always returns `stdout` with `status`.
    pub fn single(status: i32, stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            queue: RefCell::new(VecDeque::new()),
            by_subcommand: HashMap::new(),
            by_program: HashMap::new(),
            fallback: Some(RawOutput {
                status,
                stdout: stdout.into(),
            }),
            calls: RefCell::new(Vec::new()),
            program_calls: RefCell::new(Vec::new()),
        }
    }

    /// Construct a `FakeRunner` from a JSON string and exit status.
    pub fn from_json(status: i32, json: &str) -> Self {
        Self::single(status, json.as_bytes().to_vec())
    }

    /// Register a canned response for a specific subcommand (`"check"`,
    /// `"find"`, `"context"`, `"doctor"`).
    pub fn with_response(
        mut self,
        subcommand: &str,
        status: i32,
        stdout: impl Into<Vec<u8>>,
    ) -> Self {
        self.by_subcommand.insert(
            subcommand.to_owned(),
            RawOutput {
                status,
                stdout: stdout.into(),
            },
        );
        self
    }

    /// Enqueue a response to be returned on the next `run` call in FIFO order.
    pub fn push_response(&self, status: i32, stdout: impl Into<Vec<u8>>) {
        self.queue.borrow_mut().push_back(RawOutput {
            status,
            stdout: stdout.into(),
        });
    }

    /// Register a canned response for an external program (`"python3"`).
    pub fn with_program_response(
        mut self,
        program: &str,
        status: i32,
        stdout: impl Into<Vec<u8>>,
    ) -> Self {
        self.by_program.insert(
            program.to_owned(),
            RawOutput {
                status,
                stdout: stdout.into(),
            },
        );
        self
    }

    /// Return all recorded argv slices passed to `run`.
    pub fn recorded_calls(&self) -> Vec<Vec<String>> {
        self.calls.borrow().clone()
    }

    /// Return all recorded `(program, argv)` pairs passed to `run_program`.
    pub fn recorded_program_calls(&self) -> Vec<(String, Vec<String>)> {
        self.program_calls.borrow().clone()
    }
}

impl Runner for FakeRunner {
    fn run(&self, args: &[&str]) -> Result<RawOutput> {
        self.calls
            .borrow_mut()
            .push(args.iter().map(|s| (*s).to_owned()).collect());

        if let Some(next) = self.queue.borrow_mut().pop_front() {
            return Ok(next);
        }

        if let Some(sub) = args.first() {
            if let Some(found) = self.by_subcommand.get(*sub) {
                return Ok(found.clone());
            }
        }

        if let Some(fallback) = &self.fallback {
            return Ok(fallback.clone());
        }

        Ok(RawOutput {
            status: 1,
            stdout: Vec::new(),
        })
    }

    fn run_program(&self, program: &str, args: &[&str]) -> Result<RawOutput> {
        self.program_calls.borrow_mut().push((
            program.to_owned(),
            args.iter().map(|s| (*s).to_owned()).collect(),
        ));

        if let Some(found) = self.by_program.get(program) {
            return Ok(found.clone());
        }

        if let Some(fallback) = &self.fallback {
            return Ok(fallback.clone());
        }

        Ok(RawOutput {
            status: 1,
            stdout: Vec::new(),
        })
    }
}
