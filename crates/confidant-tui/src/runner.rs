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

    /// Run the `confidant` binary interactively, inheriting the terminal's
    /// stdin/stdout/stderr and without `--json`/`--no-input`. Used for
    /// editor flows like `record resolve <id> --edit` (#455), where the
    /// TUI suspends its alternate screen first. Returns the exit status.
    fn run_confidant_interactive(&self, args: &[&str]) -> Result<i32>;

    /// Run an external program interactively, inheriting the terminal's
    /// stdin/stdout/stderr. Used for the operator's `$EDITOR` on a record or
    /// note scratch file (#556 phase 2), where the TUI suspends its alternate
    /// screen first. Returns the exit status.
    fn run_program_interactive(&self, program: &str, args: &[&str]) -> Result<i32>;
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

    fn run_confidant_interactive(&self, args: &[&str]) -> Result<i32> {
        let mut cmd = Command::new(&self.bin);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }
        if let Some(vault) = &self.vault {
            if !args.contains(&"--vault") {
                cmd.arg("--vault").arg(vault);
            }
        }
        cmd.args(args);

        let status = cmd
            .status()
            .with_context(|| format!("failed to execute {}", self.bin.display()))?;
        Ok(status.code().unwrap_or(1))
    }

    fn run_program_interactive(&self, program: &str, args: &[&str]) -> Result<i32> {
        let mut cmd = Command::new(program);
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }
        cmd.args(args);

        let status = cmd
            .status()
            .with_context(|| format!("failed to execute {program}"))?;
        Ok(status.code().unwrap_or(1))
    }
}

/// In-memory fake runner for deterministic unit and snapshot tests.
#[derive(Clone, Debug, Default)]
pub struct FakeRunner {
    queue: RefCell<VecDeque<RawOutput>>,
    by_argv: RefCell<Vec<(Vec<String>, RawOutput)>>,
    by_subcommand: HashMap<String, RawOutput>,
    by_program: HashMap<String, RawOutput>,
    program_queue: RefCell<HashMap<String, VecDeque<RawOutput>>>,
    fallback: Option<RawOutput>,
    calls: RefCell<Vec<Vec<String>>>,
    program_calls: RefCell<Vec<(String, Vec<String>)>>,
    interactive_calls: RefCell<Vec<Vec<String>>>,
    interactive_program_calls: RefCell<Vec<(String, Vec<String>)>>,
    interactive_status: RefCell<i32>,
}

impl FakeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a `FakeRunner` that always returns `stdout` with `status`.
    pub fn single(status: i32, stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            queue: RefCell::new(VecDeque::new()),
            by_argv: RefCell::new(Vec::new()),
            by_subcommand: HashMap::new(),
            by_program: HashMap::new(),
            program_queue: RefCell::new(HashMap::new()),
            fallback: Some(RawOutput {
                status,
                stdout: stdout.into(),
            }),
            calls: RefCell::new(Vec::new()),
            program_calls: RefCell::new(Vec::new()),
            interactive_calls: RefCell::new(Vec::new()),
            interactive_program_calls: RefCell::new(Vec::new()),
            interactive_status: RefCell::new(0),
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

    /// Register a canned response for an argv *prefix*. The first registered
    /// prefix that matches wins, and an exact-argv match takes precedence over
    /// [`Self::with_response`] and the FIFO queue, so a test can answer
    /// `record show` and `record edit` differently (both start with
    /// `record`).
    pub fn with_argv_response(
        self,
        argv: &[&str],
        status: i32,
        stdout: impl Into<Vec<u8>>,
    ) -> Self {
        self.by_argv.borrow_mut().push((
            argv.iter().map(|s| (*s).to_owned()).collect(),
            RawOutput {
                status,
                stdout: stdout.into(),
            },
        ));
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

    /// Enqueue a response for the next `run_program` call to `program`, in
    /// FIFO order per program. Used where one program answers differently
    /// across calls (e.g. `git rev-parse` then `git check-ignore`).
    pub fn push_program_response(&self, program: &str, status: i32, stdout: impl Into<Vec<u8>>) {
        self.program_queue
            .borrow_mut()
            .entry(program.to_owned())
            .or_default()
            .push_back(RawOutput {
                status,
                stdout: stdout.into(),
            });
    }

    /// Return all recorded argv slices passed to `run`.
    pub fn recorded_calls(&self) -> Vec<Vec<String>> {
        self.calls.borrow().clone()
    }

    /// Return all recorded `(program, argv)` pairs passed to `run_program`.
    pub fn recorded_program_calls(&self) -> Vec<(String, Vec<String>)> {
        self.program_calls.borrow().clone()
    }

    /// Return all recorded argv slices passed to `run_confidant_interactive`.
    pub fn recorded_interactive_calls(&self) -> Vec<Vec<String>> {
        self.interactive_calls.borrow().clone()
    }

    /// Return all recorded `(program, argv)` pairs passed to
    /// `run_program_interactive`.
    pub fn recorded_interactive_program_calls(&self) -> Vec<(String, Vec<String>)> {
        self.interactive_program_calls.borrow().clone()
    }

    /// Set the exit status returned by `run_confidant_interactive` and
    /// `run_program_interactive`.
    pub fn set_interactive_status(&self, status: i32) {
        *self.interactive_status.borrow_mut() = status;
    }
}

/// Whether `pattern` is a prefix of `actual` (used by
/// [`FakeRunner::with_argv_response`]).
fn argv_prefix_matches(pattern: &[String], actual: &[String]) -> bool {
    !pattern.is_empty()
        && actual.len() >= pattern.len()
        && pattern.iter().zip(actual).all(|(p, a)| p == a)
}

impl Runner for FakeRunner {
    fn run(&self, args: &[&str]) -> Result<RawOutput> {
        let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        self.calls.borrow_mut().push(args.clone());

        if let Some((_, found)) = self
            .by_argv
            .borrow()
            .iter()
            .find(|(pattern, _)| argv_prefix_matches(pattern, &args))
        {
            return Ok(found.clone());
        }

        if let Some(next) = self.queue.borrow_mut().pop_front() {
            return Ok(next);
        }

        if let Some(sub) = args.first() {
            if let Some(found) = self.by_subcommand.get(sub) {
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

        if let Some(queued) = self
            .program_queue
            .borrow_mut()
            .get_mut(program)
            .and_then(VecDeque::pop_front)
        {
            return Ok(queued);
        }

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

    fn run_confidant_interactive(&self, args: &[&str]) -> Result<i32> {
        self.interactive_calls
            .borrow_mut()
            .push(args.iter().map(|s| (*s).to_owned()).collect());
        Ok(*self.interactive_status.borrow())
    }

    fn run_program_interactive(&self, program: &str, args: &[&str]) -> Result<i32> {
        self.interactive_program_calls.borrow_mut().push((
            program.to_owned(),
            args.iter().map(|s| (*s).to_owned()).collect(),
        ));
        Ok(*self.interactive_status.borrow())
    }
}
