// SPDX-License-Identifier: MIT

use super::{
    compose_pipeline, parse_document, scaffold_pipeline, ComposeInputMap,
    OverridePipelineDefinition, OverrideRefinementAction, PipelineDefinition, PipelineStageKind,
};
use crate::OVERRIDE_PIPELINE_RESULT_SCHEMA_VERSION;
use serde_json::json;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("crate should live under workspace/crates/logicpearl-pipeline")
        .to_path_buf()
}

#[test]
fn validates_basic_pipeline() {
    let pipeline = PipelineDefinition::from_json_str(
        r#"{
          "pipeline_version": "1.0",
          "pipeline_id": "demo",
          "entrypoint": "input",
          "stages": [
            {
              "id": "authz",
              "kind": "pearl",
              "artifact": "fixtures/ir/valid/auth-demo-v1.json",
              "input": {
                "member_age": "$.member.age"
              },
              "export": {
                "bitmask": "$.bitmask"
              }
            }
          ],
          "output": {
            "bitmask": "@authz.bitmask"
          }
        }"#,
    )
    .expect("pipeline parses");
    let base_dir = repo_root();
    let validated = pipeline.validate(base_dir).expect("pipeline validates");
    assert_eq!(validated.pipeline_id, "demo");
    assert_eq!(validated.stage_count, 1);
    assert_eq!(validated.stages[0].kind, PipelineStageKind::Pearl);
}

#[test]
fn rejects_pipeline_stage_paths_that_escape_base_dir() {
    let pipeline = PipelineDefinition::from_json_str(
        r#"{
          "pipeline_version": "1.0",
          "pipeline_id": "demo",
          "entrypoint": "input",
          "stages": [
            {
              "id": "authz",
              "kind": "pearl",
              "artifact": "../fixtures/ir/valid/auth-demo-v1.json",
              "input": {
                "member_age": "$.member.age"
              },
              "export": {
                "bitmask": "$.bitmask"
              }
            }
          ],
          "output": {
            "bitmask": "@authz.bitmask"
          }
        }"#,
    )
    .expect("pipeline parses");
    let err = pipeline
        .validate(repo_root())
        .expect_err("escaping stage paths should fail");
    assert!(err.to_string().contains("escapes bundle directory"));
}

#[test]
fn rejects_absolute_pipeline_stage_paths() {
    let pipeline = PipelineDefinition::from_json_str(
        r#"{
          "pipeline_version": "1.0",
          "pipeline_id": "demo",
          "entrypoint": "input",
          "stages": [
            {
              "id": "authz",
              "kind": "pearl",
              "artifact": "/tmp/auth-demo-v1.json",
              "input": {
                "member_age": "$.member.age"
              },
              "export": {
                "bitmask": "$.bitmask"
              }
            }
          ],
          "output": {
            "bitmask": "@authz.bitmask"
          }
        }"#,
    )
    .expect("pipeline parses");
    let err = pipeline
        .validate(repo_root())
        .expect_err("absolute stage paths should fail");
    assert!(err.to_string().contains("must be relative"));
}

#[test]
fn rejects_future_stage_reference() {
    let pipeline = PipelineDefinition::from_json_str(
        r#"{
          "pipeline_version": "1.0",
          "pipeline_id": "demo",
          "entrypoint": "input",
          "stages": [
            {
              "id": "authz",
              "kind": "pearl",
              "artifact": "fixtures/ir/valid/auth-demo-v1.json",
              "input": {
                "member_age": "@later.bitmask"
              },
              "export": {
                "bitmask": "$.bitmask"
              }
            }
          ],
          "output": {
            "bitmask": "@authz.bitmask"
          }
        }"#,
    )
    .expect("pipeline parses");
    let base_dir = repo_root();
    let err = pipeline
        .validate(base_dir)
        .expect_err("validation should fail");
    assert!(err.to_string().contains("unknown or future stage"));
}

#[test]
fn runs_basic_pearl_pipeline() {
    let pipeline = PipelineDefinition::from_json_str(
        r#"{
          "pipeline_version": "1.0",
          "pipeline_id": "demo",
          "entrypoint": "input",
          "stages": [
            {
              "id": "authz",
              "kind": "pearl",
              "artifact": "fixtures/ir/valid/auth-demo-v1.json",
              "input": {
                "action": "$.request.action",
                "resource_archived": "$.request.resource_archived",
                "user_role": "$.user.role",
                "failed_attempts": "$.user.failed_attempts"
              },
              "export": {
                "bitmask": "$.bitmask",
                "allow": "$.allow"
              }
            }
          ],
          "output": {
            "bitmask": "@authz.bitmask",
            "allow": "@authz.allow"
          }
        }"#,
    )
    .expect("pipeline parses");
    let base_dir = repo_root();
    let input = json!({
        "request": {
            "action": "delete",
            "resource_archived": true
        },
        "user": {
            "role": "viewer",
            "failed_attempts": 99
        }
    });
    let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
    assert_eq!(execution.output.get("bitmask"), Some(&json!(7)));
    assert_eq!(execution.output.get("allow"), Some(&json!(false)));
}

#[test]
fn runs_observer_then_pearl_pipeline() {
    let pipeline = PipelineDefinition::from_json_str(
        r#"{
          "pipeline_version": "1.0",
          "pipeline_id": "observer_demo",
          "entrypoint": "input",
          "stages": [
            {
              "id": "observer",
              "kind": "observer_plugin",
              "plugin_manifest": "examples/plugins/python_observer/manifest.json",
              "input": {
                "age": "$.age",
                "member": "$.member",
                "country": "$.country"
              },
              "export": {
                "age": "$.features.age",
                "is_member": "$.features.is_member"
              }
            },
            {
              "id": "gate",
              "kind": "pearl",
              "artifact": "fixtures/ir/valid/membership-demo-v1.json",
              "input": {
                "age": "@observer.age",
                "is_member": "@observer.is_member"
              },
              "export": {
                "bitmask": "$.bitmask",
                "allow": "$.allow"
              }
            }
          ],
          "output": {
            "bitmask": "@gate.bitmask",
            "allow": "@gate.allow"
          }
        }"#,
    )
    .expect("pipeline parses");
    let base_dir = repo_root();
    let input = json!({
        "age": 34,
        "member": true,
        "country": "US"
    });
    let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
    assert_eq!(execution.output.get("bitmask"), Some(&json!(0)));
    assert_eq!(execution.output.get("allow"), Some(&json!(true)));
}

#[test]
fn runs_observer_pearl_verify_pipeline() {
    let pipeline = PipelineDefinition::from_json_str(
        r#"{
          "pipeline_version": "1.0",
          "pipeline_id": "observer_verify_demo",
          "entrypoint": "input",
          "stages": [
            {
              "id": "observer",
              "kind": "observer_plugin",
              "plugin_manifest": "examples/plugins/python_observer/manifest.json",
              "input": {
                "age": "$.age",
                "member": "$.member",
                "country": "$.country"
              },
              "export": {
                "age": "$.features.age",
                "is_member": "$.features.is_member"
              }
            },
            {
              "id": "gate",
              "kind": "pearl",
              "artifact": "fixtures/ir/valid/membership-demo-v1.json",
              "input": {
                "age": "@observer.age",
                "is_member": "@observer.is_member"
              },
              "export": {
                "bitmask": "$.bitmask",
                "allow": "$.allow"
              }
            },
            {
              "id": "audit",
              "kind": "verify_plugin",
              "plugin_manifest": "examples/plugins/python_pipeline_verify/manifest.json",
              "input": {
                "bitmask": "@gate.bitmask",
                "allow": "@gate.allow"
              },
              "export": {
                "audit_status": "$.audit_status",
                "consistent": "$.summary.consistent"
              }
            }
          ],
          "output": {
            "bitmask": "@gate.bitmask",
            "allow": "@gate.allow",
            "audit_status": "@audit.audit_status",
            "consistent": "@audit.consistent"
          }
        }"#,
    )
    .expect("pipeline parses");
    let base_dir = repo_root();
    let input = json!({
        "age": 34,
        "member": true,
        "country": "US"
    });
    let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
    assert_eq!(execution.output.get("bitmask"), Some(&json!(0)));
    assert_eq!(execution.output.get("allow"), Some(&json!(true)));
    assert_eq!(
        execution.output.get("audit_status"),
        Some(&json!("clean_pass"))
    );
    assert_eq!(execution.output.get("consistent"), Some(&json!(true)));
}

#[test]
fn runs_trace_source_plugin_pipeline() {
    let pipeline = PipelineDefinition::from_json_str(
        r#"{
          "pipeline_version": "1.0",
          "pipeline_id": "trace_source_demo",
          "entrypoint": "input",
          "stages": [
            {
              "id": "trace_source",
              "kind": "trace_source_plugin",
              "plugin_manifest": "examples/plugins/python_trace_source/manifest.json",
              "payload": "$.source",
              "options": {
                "label_column": "$.label_column"
              },
              "export": {
                "decision_traces": "$.decision_traces"
              }
            }
          ],
          "output": {
            "decision_traces": "@trace_source.decision_traces"
          }
        }"#,
    )
    .expect("pipeline parses");
    let base_dir = repo_root();
    let input = json!({
        "source": Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/getting_started/decision_traces.csv")
            .display()
            .to_string(),
        "label_column": "allowed"
    });
    let execution = pipeline.run(base_dir, &input).expect("pipeline runs");
    let rows = execution
        .output
        .get("decision_traces")
        .and_then(|value| value.as_array())
        .expect("pipeline should export decision traces");
    assert!(!rows.is_empty());
    assert!(rows[0].get("features").is_some());
    assert!(rows[0].get("allowed").is_some());
}

#[test]
fn composes_runnable_pipeline_from_artifacts_and_input_map() {
    let base_dir = repo_root();
    let artifact_paths = vec![base_dir.join("fixtures/ir/valid/auth-demo-v1.json")];
    let input_map = ComposeInputMap::from_json_str(
        r#"{
          "features": {
            "action": "$.request.action",
            "resource_archived": "$.request.resource_archived",
            "user_role": "$.user.role",
            "failed_attempts": "$.user.failed_attempts"
          }
        }"#,
    )
    .expect("input map parses");
    let plan =
        compose_pipeline("starter", &artifact_paths, &base_dir, &input_map).expect("compose works");
    assert_eq!(plan.pipeline.pipeline_id, "starter");
    assert_eq!(plan.pipeline.stages.len(), 1);
    assert_eq!(plan.pipeline.stages[0].id, "auth_demo_v1");
    assert_eq!(
        plan.pipeline.stages[0].artifact.as_deref(),
        Some("fixtures/ir/valid/auth-demo-v1.json")
    );
    assert!(plan.pipeline.stages[0].input.contains_key("action"));
    assert_eq!(
        plan.pipeline.output.get("allow"),
        Some(&json!("@auth_demo_v1.allow"))
    );

    let execution = plan
        .pipeline
        .run(
            &base_dir,
            &json!({
                "request": {
                    "action": "delete",
                    "resource_archived": true
                },
                "user": {
                    "role": "viewer",
                    "failed_attempts": 99
                }
            }),
        )
        .expect("composed pipeline runs");
    assert_eq!(execution.output.get("allow"), Some(&json!(false)));
}

#[test]
fn compose_requires_input_map_for_every_feature() {
    let base_dir = repo_root();
    let artifact_paths = vec![base_dir.join("fixtures/ir/valid/auth-demo-v1.json")];
    let input_map = ComposeInputMap::from_json_str(
        r#"{
          "features": {
            "action": "$.request.action"
          }
        }"#,
    )
    .expect("input map parses");
    let err = compose_pipeline("starter", &artifact_paths, &base_dir, &input_map)
        .expect_err("missing feature mapping should fail");
    assert!(err.to_string().contains("resource_archived"));
}

#[test]
fn scaffolds_draft_pipeline_with_explicit_placeholders() {
    let base_dir = repo_root();
    let artifact_paths = vec![base_dir.join("fixtures/ir/valid/auth-demo-v1.json")];
    let plan = scaffold_pipeline("starter", &artifact_paths, &base_dir).expect("scaffold works");
    assert_eq!(
        plan.pipeline.stages[0].input.get("action"),
        Some(&json!("$.TODO_action"))
    );
    assert!(plan.notes[0].contains("not runnable"));
}

#[test]
fn runs_override_pipeline_with_first_matching_refinement() {
    let pipeline = OverridePipelineDefinition::from_json_str(
        r#"{
          "schema_version": "logicpearl.override_pipeline.v1",
          "pipeline_id": "override_demo",
          "base": {
            "id": "statute",
            "artifact": "fixtures/ir/valid/auth-demo-v1.json",
            "input": {
              "action": "$.action",
              "resource_archived": "$.resource_archived",
              "user_role": "$.user_role",
              "failed_attempts": "$.failed_attempts"
            }
          },
          "refinements": [
            {
              "id": "membership_case",
              "artifact": "fixtures/ir/valid/membership-demo-v1.json",
              "action": "override_if_fires",
              "input": {
                "age": "$.age",
                "is_member": "$.is_member"
              }
            }
          ]
        }"#,
    )
    .expect("override pipeline parses");
    let base_dir = repo_root();
    let validated = pipeline
        .validate(&base_dir)
        .expect("override pipeline validates");
    assert_eq!(validated.base.id, "statute");
    assert_eq!(validated.refinements[0].id, "membership_case");

    let input = json!({
        "action": "read",
        "resource_archived": false,
        "user_role": "admin",
        "failed_attempts": 0,
        "age": 16,
        "is_member": 1
    });
    let execution = pipeline
        .run(&base_dir, &input)
        .expect("override pipeline runs");

    assert_eq!(
        execution.schema_version,
        OVERRIDE_PIPELINE_RESULT_SCHEMA_VERSION
    );
    assert_eq!(execution.selected, "membership_case");
    assert!(!execution.base.fired);
    assert!(execution.base.effect_applied);
    assert!(execution.refinements[0].fired);
    assert!(execution.refinements[0].effect_applied);
    assert_eq!(execution.output["decision_kind"], "gate");
    assert_eq!(execution.output["allow"], false);
    assert_eq!(execution.stages.len(), 2);
}

#[test]
fn parses_override_pipeline_yaml_shorthand() {
    let pipeline: OverridePipelineDefinition = parse_document(
        r#"schema_version: logicpearl.override_pipeline.v1
pipeline_id: shorthand_demo
base: fixtures/ir/valid/auth-demo-v1.json
refinements:
  - id: membership_case
    artifact: fixtures/ir/valid/membership-demo-v1.json
    action: override_if_fires
"#,
    )
    .expect("override pipeline shorthand parses");

    assert_eq!(
        pipeline.base.artifact,
        "fixtures/ir/valid/auth-demo-v1.json"
    );
    assert_eq!(
        pipeline.refinements[0].artifact,
        "fixtures/ir/valid/membership-demo-v1.json"
    );
    assert_eq!(
        pipeline.refinements[0].action,
        Some(OverrideRefinementAction::OverrideIfFires)
    );
}

#[test]
fn override_pipeline_rejects_old_pearl_alias() {
    let err = parse_document::<OverridePipelineDefinition>(
        r#"schema_version: logicpearl.override_pipeline.v1
pipeline_id: shorthand_demo
base:
  id: statute
  pearl: fixtures/ir/valid/auth-demo-v1.json
refinements:
  - id: membership_case
    artifact: fixtures/ir/valid/membership-demo-v1.json
    action: override_if_fires
"#,
    )
    .expect_err("old pearl alias should be rejected");

    assert!(err
        .to_string()
        .contains("data did not match any variant of untagged enum OverridePearlInput"));
}

#[test]
fn override_pipeline_passes_when_no_refinement_fires() {
    let pipeline = OverridePipelineDefinition::from_json_str(
        r#"{
          "schema_version": "logicpearl.override_pipeline.v1",
          "pipeline_id": "override_demo",
          "base": {
            "id": "statute",
            "artifact": "fixtures/ir/valid/auth-demo-v1.json"
          },
          "refinements": [
            {
              "id": "membership_case",
              "artifact": "fixtures/ir/valid/membership-demo-v1.json",
              "action": "override_if_fires"
            }
          ]
        }"#,
    )
    .expect("override pipeline parses");
    let input = json!({
        "action": "read",
        "resource_archived": false,
        "user_role": "admin",
        "failed_attempts": 0,
        "age": 34,
        "is_member": 1
    });
    let execution = pipeline
        .run(repo_root(), &input)
        .expect("override pipeline runs");

    assert_eq!(execution.selected, "statute");
    assert_eq!(execution.output["allow"], true);
    assert!(!execution.refinements[0].fired);
    assert!(!execution.refinements[0].effect_applied);
}
