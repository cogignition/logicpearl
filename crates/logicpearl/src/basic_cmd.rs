// SPDX-License-Identifier: MIT
use super::*;

mod action_build;
mod args;
mod build;
mod build_inputs;
mod compile;
mod compose;
mod config;
mod conflicts;
mod discover;
mod doctor;
mod fanout_build;
mod feature_dictionary;
mod inspect;
mod package;
mod post_build_summary;
mod progress;
mod quickstart;
mod review_loop;
mod run;
mod shared_args;
mod verify;

use action_build::run_action_build;
pub(crate) use args::{
    BuildArgs, CompileArgs, ComposeArgs, DiscoverArgs, DoctorArgs, InspectArgs, PackageArgs,
    QuickstartArgs, RefineArgs, ReviewArgs, RunArgs, TraceArgs, VerifyArgs,
};
pub(crate) use build::run_build;
use build_inputs::{
    build_trace_plugin_options, default_gate_id_from_path, feature_column_selection,
    parse_key_value_entries,
};
pub(crate) use compile::run_compile;
pub(crate) use compose::run_compose;
pub(crate) use discover::run_discover;
pub(crate) use doctor::run_doctor;
use fanout_build::run_fanout_build;
use feature_dictionary::{
    feature_columns_from_decision_rows, generated_feature_dictionary_for_output,
    generated_feature_dictionary_path, should_generate_feature_dictionary,
    write_feature_dictionary_from_columns,
};
pub(crate) use inspect::run_inspect;
pub(crate) use package::run_package;
use progress::{
    finish_progress, progress_callback, progress_enabled, set_progress_message, start_progress,
};
pub(crate) use quickstart::run_quickstart;
pub(crate) use review_loop::{run_refine, run_review, run_trace};
pub(crate) use run::run_eval;
pub(crate) use shared_args::{
    selection_policy_from_args, to_discovery_decision_mode, ActionSelectionArg,
    DiscoveryDecisionModeArg, ProposalPolicyArg, QuickstartTopic, SelectionPolicyArg,
};
pub(crate) use verify::run_verify;
