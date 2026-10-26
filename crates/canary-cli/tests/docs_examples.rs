//! Runs the command examples from the documentation site against the CLI
//! (`[E-102]`, issue #511).
//!
//! Every `stellar-canary ...` line in a fenced `bash`/`sh`/`console` block
//! under `docs-site/src` is checked against the binary that was just built:
//! its subcommand path must exist and every long flag it uses must be listed
//! by that subcommand's `--help`. A flag that is renamed or removed from the
//! CLI therefore fails here instead of in a user's terminal.
//!
//! Nothing is executed: the command's own arguments are never run, only
//! `--help` for its subcommand, so the check needs no network, fixtures or
//! workspace.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The binary this package just built.
const BIN: &str = env!("CARGO_BIN_EXE_stellar-canary");

/// Every Markdown file under the documentation site, in a stable order.
fn doc_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{} is readable: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("directory entry is readable").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                out.push(path);
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs-site/src");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();
    assert!(
        !files.is_empty(),
        "no documentation pages found at {}",
        root.display()
    );
    files
}

/// The commands in the `bash`, `sh` and `console` blocks of one page.
fn documented_commands(doc: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut fence: Option<&str> = None;
    let mut block: Vec<String> = Vec::new();

    for line in doc.replace("\r\n", "\n").lines() {
        let trimmed = line.trim();
        if let Some(info) = trimmed.strip_prefix("```") {
            match fence {
                None => {
                    fence = Some(info.trim());
                    block.clear();
                }
                Some(info_string) => {
                    if matches!(info_string, "bash" | "sh" | "console" | "shell") {
                        commands.extend(commands_in_block(&block));
                    }
                    fence = None;
                    block.clear();
                }
            }
            continue;
        }
        if fence.is_some() {
            block.push(line.to_string());
        }
    }

    commands
}

/// Joins continuation lines, then keeps the lines that run the CLI.
fn commands_in_block(block: &[String]) -> Vec<String> {
    let mut commands = Vec::new();
    let mut current = String::new();
    let mut pending = false;

    for line in block {
        let text = line.trim();
        if text.starts_with('#') {
            continue;
        }
        // Drop a trailing comment that is not inside the command itself.
        let text = match text.find(" #") {
            Some(at) => text[..at].trim_end(),
            None => text,
        };
        if let Some(without_line_continuation) = text.strip_suffix('\\') {
            current.push_str(without_line_continuation);
            current.push(' ');
            pending = true;
            continue;
        }
        current.push_str(text);
        if pending {
            commands.push(current.trim().to_string());
            current.clear();
            pending = false;
        } else if !current.trim().is_empty() {
            commands.push(current.trim().to_string());
            current.clear();
        }
    }
    if !current.trim().is_empty() {
        commands.push(current.trim().to_string());
    }

    commands
        .into_iter()
        .filter_map(|command| {
            let command = command.strip_prefix("$ ").unwrap_or(&command).trim();
            command
                .starts_with("stellar-canary ")
                .then(|| command.to_string())
        })
        .collect()
}

/// Splits a command line into arguments, honouring single and double quotes.
fn tokenize(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for c in command.chars() {
        match quote {
            Some(open) if c == open => quote = None,
            Some(_) => current.push(c),
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// The tokens after `stellar-canary` that name a subcommand, stopping at the
/// first flag or argument that is not a plain subcommand name.
fn subcommand_path(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .skip(1)
        .take_while(|token| {
            !token.starts_with('-')
                && token.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && token
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
        .cloned()
        .collect()
}

/// The long flags a command uses, without their `=value` part.
fn long_flags(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .skip(1)
        .filter(|token| token.starts_with("--") && token.as_str() != "--help")
        .map(|token| token.split('=').next().unwrap_or(token).to_string())
        .collect()
}

/// Runs `stellar-canary <subcommand> --help` and returns the flags the
/// command uses that its help does not list.
fn missing_flags(command: &str) -> Vec<String> {
    let tokens = tokenize(command);
    let subcommands = subcommand_path(&tokens);
    let output = Command::new(BIN)
        .args(&subcommands)
        .arg("--help")
        .output()
        .unwrap_or_else(|e| panic!("could not run {BIN}: {e}"));
    let help = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "`{command}`: `stellar-canary {} --help` failed ({}):\n{}",
        subcommands.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    long_flags(&tokens)
        .into_iter()
        .filter(|flag| !help.contains(flag.as_str()))
        .collect()
}

#[test]
fn every_documented_command_example_still_parses() {
    let mut checked = 0;
    let mut failures = Vec::new();

    for path in doc_files() {
        let doc = std::fs::read_to_string(&path).expect("documentation page is readable");
        for command in documented_commands(&doc) {
            checked += 1;
            for flag in missing_flags(&command) {
                failures.push(format!("{}: `{command}` uses {flag}", path.display()));
            }
        }
    }

    assert!(
        checked >= 10,
        "expected at least 10 documented command examples, found {checked}; \
         the extraction moved and this test is no longer looking at the docs"
    );
    assert!(
        failures.is_empty(),
        "documented commands no longer match the CLI:\n{}",
        failures.join("\n")
    );
}

#[test]
fn a_flag_the_cli_does_not_define_is_reported() {
    // The negative side of the check: a documented flag that no subcommand
    // defines must be reported, so a stale example fails the suite.
    let missing = missing_flags("stellar-canary check --definitely-not-a-flag");
    assert_eq!(missing, vec!["--definitely-not-a-flag".to_string()]);
}
