// SPDX-License-Identifier: MIT
use anstream::println;
use logicpearl_core::{
    load_artifact_bundle, manifest_file_roles, ArtifactKind, ArtifactManifestFiles,
    ArtifactManifestV1, LoadedArtifactBundle, ARTIFACT_MANIFEST_SCHEMA_VERSION,
};
use logicpearl_ir::{LogicPearlActionIr, LogicPearlGateIr};
use logicpearl_pipeline::PipelineDefinition;
use logicpearl_runtime::artifact_hash;
use miette::{IntoDiagnostic, Result, WrapErr};
use owo_colors::OwoColorize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

use super::{
    hash_file_canonical_if_json, read_json_file, resolve_manifest_member_path, ArtifactDigestArgs,
    ArtifactInspectArgs, ArtifactVerifyArgs,
};

#[derive(Debug, Clone, Serialize)]
struct ArtifactManifestInspection {
    manifest_path: Option<String>,
    artifact_dir: String,
    manifest: ArtifactManifestV1,
    resolved_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactDigestReport {
    manifest_path: Option<String>,
    artifact_id: String,
    artifact_kind: ArtifactKind,
    artifact_hash: String,
    bundle_hash: Option<String>,
    file_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactVerificationReport {
    ok: bool,
    manifest_path: Option<String>,
    artifact_id: Option<String>,
    artifact_kind: Option<ArtifactKind>,
    checks: Vec<ArtifactVerificationCheck>,
}

#[derive(Debug, Clone, Serialize)]
struct ArtifactVerificationCheck {
    name: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

pub(crate) fn run_artifact_inspect(args: ArtifactInspectArgs) -> Result<()> {
    let inspection = inspect_artifact(&args.artifact)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&inspection).into_diagnostic()?
        );
    } else {
        println!(
            "{} {}",
            "Artifact".bold().bright_cyan(),
            inspection.manifest.artifact_id.bold()
        );
        println!(
            "  {} {:?}",
            "Kind".bright_black(),
            inspection.manifest.artifact_kind
        );
        println!(
            "  {} {}",
            "Schema".bright_black(),
            inspection.manifest.schema_version
        );
        println!(
            "  {} {}",
            "Artifact hash".bright_black(),
            inspection.manifest.artifact_hash
        );
        if let Some(bundle_hash) = &inspection.manifest.bundle_hash {
            println!("  {} {}", "Bundle hash".bright_black(), bundle_hash);
        }
        println!("  {} {}", "IR".bright_black(), inspection.manifest.files.ir);
        for (role, path) in &inspection.resolved_files {
            println!("  {} {} {}", "File".bright_black(), role, path);
        }
    }
    Ok(())
}

pub(crate) fn run_artifact_digest(args: ArtifactDigestArgs) -> Result<()> {
    let inspection = inspect_artifact(&args.artifact)?;
    let report = ArtifactDigestReport {
        manifest_path: inspection.manifest_path,
        artifact_id: inspection.manifest.artifact_id,
        artifact_kind: inspection.manifest.artifact_kind,
        artifact_hash: inspection.manifest.artifact_hash,
        bundle_hash: inspection.manifest.bundle_hash,
        file_hashes: inspection.manifest.file_hashes,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        println!("{}", report.artifact_hash);
        if let Some(bundle_hash) = &report.bundle_hash {
            println!("bundle {bundle_hash}");
        }
    }
    Ok(())
}

pub(crate) fn run_artifact_verify(args: ArtifactVerifyArgs) -> Result<()> {
    let report = verify_artifact(&args.artifact)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else if report.ok {
        println!(
            "{} {}",
            "Verified".bold().bright_green(),
            report.artifact_id.as_deref().unwrap_or("artifact").bold()
        );
        for check in &report.checks {
            println!("  {} {}", "ok".bright_black(), check.name);
        }
    } else {
        println!("{}", "Artifact verification failed".bold().bright_red());
        for check in &report.checks {
            let status = if check.ok { "ok" } else { "fail" };
            if let Some(message) = &check.message {
                println!("  {} {} - {}", status.bright_black(), check.name, message);
            } else {
                println!("  {} {}", status.bright_black(), check.name);
            }
        }
    }
    if report.ok {
        Ok(())
    } else {
        Err(miette::miette!("artifact verification failed"))
    }
}

fn inspect_artifact(path: &Path) -> Result<ArtifactManifestInspection> {
    let context = load_artifact_manifest_context(path)?;
    let resolved_files = resolved_manifest_files(&context.base_dir, &context.manifest.files)?;
    Ok(ArtifactManifestInspection {
        manifest_path: context
            .manifest_path
            .as_ref()
            .map(|path| path.display().to_string()),
        artifact_dir: context.base_dir.display().to_string(),
        manifest: context.manifest,
        resolved_files,
    })
}

fn verify_artifact(path: &Path) -> Result<ArtifactVerificationReport> {
    let context = load_artifact_manifest_context(path)?;
    let mut checks = Vec::new();
    let raw_schema_version = context.raw_manifest.as_ref().and_then(|value| {
        value
            .get("schema_version")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    });
    push_check(
        &mut checks,
        "schema_version",
        raw_schema_version.as_deref() == Some(ARTIFACT_MANIFEST_SCHEMA_VERSION),
        raw_schema_version
            .as_deref()
            .filter(|value| *value != ARTIFACT_MANIFEST_SCHEMA_VERSION)
            .map(|value| format!("expected {ARTIFACT_MANIFEST_SCHEMA_VERSION}, found {value}"))
            .or_else(|| {
                if raw_schema_version.is_none() {
                    Some(format!("expected {ARTIFACT_MANIFEST_SCHEMA_VERSION}"))
                } else {
                    None
                }
            }),
    );

    let ir_path = resolve_manifest_member_path(&context.base_dir, &context.manifest.files.ir)?;
    push_check(
        &mut checks,
        "files.ir_exists",
        ir_path.exists(),
        (!ir_path.exists()).then(|| format!("missing {}", ir_path.display())),
    );

    if ir_path.exists() {
        let ir_value = read_json_file(&ir_path)?;
        let actual_hash = artifact_hash(&ir_value);
        push_check(
            &mut checks,
            "artifact_hash",
            actual_hash == context.manifest.artifact_hash,
            (actual_hash != context.manifest.artifact_hash).then(|| {
                format!(
                    "expected {}, computed {}",
                    context.manifest.artifact_hash, actual_hash
                )
            }),
        );
        match validate_manifest_kind_and_ir(&context.manifest, &context.base_dir, &ir_path) {
            Ok(()) => push_check(&mut checks, "ir_valid", true, None),
            Err(err) => push_check(&mut checks, "ir_valid", false, Some(err.to_string())),
        }
        if let Some(expected) = &context.manifest.input_schema_hash {
            let actual = ir_value.get("input_schema").map(artifact_hash);
            push_check(
                &mut checks,
                "input_schema_hash",
                actual.as_ref() == Some(expected),
                (actual.as_ref() != Some(expected)).then(|| {
                    format!(
                        "expected {}, computed {}",
                        expected,
                        actual.unwrap_or_else(|| "missing input_schema".to_string())
                    )
                }),
            );
        }
    }

    for (role, relative_path) in manifest_file_roles(&context.manifest.files)
        .into_iter()
        .filter(|(role, _)| role != "ir")
    {
        let path = resolve_manifest_member_path(&context.base_dir, &relative_path)?;
        push_check(
            &mut checks,
            format!("files.{role}_exists"),
            path.exists(),
            (!path.exists()).then(|| format!("missing {}", path.display())),
        );
        if path.exists() {
            let actual = hash_file_canonical_if_json(&path)?;
            if let Some(expected) = context.manifest.file_hashes.get(&role) {
                push_check(
                    &mut checks,
                    format!("file_hashes.{role}"),
                    &actual == expected,
                    (&actual != expected)
                        .then(|| format!("expected {expected}, computed {actual}")),
                );
            }
        }
    }

    if let (Some(path), Some(expected)) = (
        context.manifest.files.feature_dictionary.as_ref(),
        context.manifest.feature_dictionary_hash.as_ref(),
    ) {
        let dictionary_path = resolve_manifest_member_path(&context.base_dir, path)?;
        if dictionary_path.exists() {
            let actual = hash_file_canonical_if_json(&dictionary_path)?;
            push_check(
                &mut checks,
                "feature_dictionary_hash",
                &actual == expected,
                (&actual != expected).then(|| format!("expected {expected}, computed {actual}")),
            );
        }
    }

    push_check(
        &mut checks,
        "build_options_hash_format",
        context
            .manifest
            .build_options_hash
            .as_ref()
            .map(|value| value.starts_with("sha256:"))
            .unwrap_or(true),
        context
            .manifest
            .build_options_hash
            .as_ref()
            .filter(|value| !value.starts_with("sha256:"))
            .map(|value| format!("not a sha256 digest: {value}")),
    );

    let ok = checks.iter().all(|check| check.ok);
    Ok(ArtifactVerificationReport {
        ok,
        manifest_path: context
            .manifest_path
            .as_ref()
            .map(|path| path.display().to_string()),
        artifact_id: Some(context.manifest.artifact_id),
        artifact_kind: Some(context.manifest.artifact_kind),
        checks,
    })
}

fn push_check(
    checks: &mut Vec<ArtifactVerificationCheck>,
    name: impl Into<String>,
    ok: bool,
    message: Option<String>,
) {
    checks.push(ArtifactVerificationCheck {
        name: name.into(),
        ok,
        message,
    });
}

pub(super) fn load_artifact_manifest_context(path: &Path) -> Result<LoadedArtifactBundle> {
    load_artifact_bundle(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to load artifact manifest {}", path.display()))
}

fn validate_manifest_kind_and_ir(
    manifest: &ArtifactManifestV1,
    base_dir: &Path,
    ir_path: &Path,
) -> Result<()> {
    match manifest.artifact_kind {
        ArtifactKind::Gate => {
            let gate = LogicPearlGateIr::from_path(ir_path)
                .into_diagnostic()
                .wrap_err("could not parse gate IR")?;
            gate.validate()
                .into_diagnostic()
                .wrap_err("gate IR did not validate")?;
            if gate.gate_id != manifest.artifact_id {
                return Err(miette::miette!(
                    "manifest artifact_id {} does not match gate_id {}",
                    manifest.artifact_id,
                    gate.gate_id
                ));
            }
        }
        ArtifactKind::Action => {
            let policy = LogicPearlActionIr::from_path(ir_path)
                .into_diagnostic()
                .wrap_err("could not parse action policy IR")?;
            policy
                .validate()
                .into_diagnostic()
                .wrap_err("action policy IR did not validate")?;
            if policy.action_policy_id != manifest.artifact_id {
                return Err(miette::miette!(
                    "manifest artifact_id {} does not match action_policy_id {}",
                    manifest.artifact_id,
                    policy.action_policy_id
                ));
            }
        }
        ArtifactKind::Pipeline => {
            let pipeline = PipelineDefinition::from_path(ir_path)
                .into_diagnostic()
                .wrap_err("could not parse pipeline definition")?;
            let pipeline_base = if ir_path.is_absolute() {
                ir_path.parent().unwrap_or(base_dir)
            } else {
                base_dir
            };
            pipeline
                .validate(pipeline_base)
                .into_diagnostic()
                .wrap_err("pipeline definition did not validate")?;
            if pipeline.pipeline_id != manifest.artifact_id {
                return Err(miette::miette!(
                    "manifest artifact_id {} does not match pipeline_id {}",
                    manifest.artifact_id,
                    pipeline.pipeline_id
                ));
            }
        }
    }
    Ok(())
}

fn resolved_manifest_files(
    base_dir: &Path,
    files: &ArtifactManifestFiles,
) -> Result<BTreeMap<String, String>> {
    manifest_file_roles(files)
        .into_iter()
        .map(|(role, path)| {
            let resolved = resolve_manifest_member_path(base_dir, &path)
                .wrap_err_with(|| format!("invalid manifest file path for {role}"))?;
            Ok((role, resolved.display().to_string()))
        })
        .collect()
}
