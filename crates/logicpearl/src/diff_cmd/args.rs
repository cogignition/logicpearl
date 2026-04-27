// SPDX-License-Identifier: MIT
use clap::Args;
use std::path::PathBuf;

const DIFF_AFTER_HELP: &str = "\
Examples:
  logicpearl diff old_output new_output
  logicpearl diff old_output/artifact.json new_output/artifact.json --json
  logicpearl diff old_output/pearl.ir.json new_output/pearl.ir.json";

#[derive(Debug, Args)]
#[command(after_help = DIFF_AFTER_HELP)]
pub(crate) struct DiffArgs {
    /// Older artifact bundle directory, artifact.json, or pearl.ir.json path.
    pub old_artifact: PathBuf,
    /// Newer artifact bundle directory, artifact.json, or pearl.ir.json path.
    pub new_artifact: PathBuf,
    /// Emit machine-readable JSON instead of styled terminal output.
    #[arg(long)]
    pub json: bool,
}
