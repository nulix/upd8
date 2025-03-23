use anyhow::{Result, Context, anyhow};
use log::{debug, error};
use std::process::Command;

/// Executes an external command with specified arguments and provides detailed error reporting.
///
/// # Arguments
/// * `cmd` - The command executable as a string slice (e.g., "curl", "ls").
/// * `args` - A slice of string slices representing the arguments to the command.
///
/// # Returns
/// `Ok(())` if the command executes successfully (exit code 0).
/// `Err(anyhow::Error)` if the command fails to execute or returns a non-zero exit code.
pub fn exec_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    debug!("Executing command: '{} {}'", cmd, args.join(" "));

    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute command: '{} {}'", cmd, args.join(" ")))?;

    if output.status.success() {
        debug!("Command '{} {}' executed successfully.", cmd, args.join(" "));
        // Optionally, you might want to return stdout here if the command has meaningful output
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let error_message = format!(
            "Command '{} {}' failed. Exit code: {:?}\nStdout: {}\nStderr: {}",
            cmd,
            args.join(" "),
            output.status.code(),
            stdout,
            stderr
        );
        error!("{}", error_message);
        Err(anyhow!(error_message))
    }
}
