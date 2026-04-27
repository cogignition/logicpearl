// SPDX-License-Identifier: MIT
use super::model::DiffPearl;
use crate::Result;
use logicpearl_ir::{LogicPearlActionIr, LogicPearlGateIr};
use miette::{Context, IntoDiagnostic};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

pub(super) fn load_diff_pearl(path: &PathBuf) -> Result<DiffPearl> {
    let payload = fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err("failed to read pearl IR")?;
    let value: Value = serde_json::from_str(&payload)
        .into_diagnostic()
        .wrap_err("pearl IR is not valid JSON")?;
    if value.get("action_policy_id").is_some() {
        return LogicPearlActionIr::from_json_str(&payload)
            .into_diagnostic()
            .map(DiffPearl::Action)
            .wrap_err("pearl IR is not a valid action policy");
    }
    LogicPearlGateIr::from_json_str(&payload)
        .into_diagnostic()
        .map(DiffPearl::Gate)
        .wrap_err("pearl IR is not a valid gate")
}
