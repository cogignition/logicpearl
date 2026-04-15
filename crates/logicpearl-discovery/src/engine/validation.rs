// SPDX-License-Identifier: MIT
use serde_json::Value;
use std::collections::BTreeMap;

use super::super::DecisionTraceRow;

const DISCOVERY_VALIDATION_MIN_CLASS_ROWS: usize = 20;
const DISCOVERY_VALIDATION_FRACTION_NUMERATOR: usize = 1;
const DISCOVERY_VALIDATION_FRACTION_DENOMINATOR: usize = 5;

#[derive(Debug, Clone)]
pub(super) struct DiscoveryValidationSplit {
    pub(super) train_denied_indices: Vec<usize>,
    pub(super) train_allowed_indices: Vec<usize>,
    pub(super) validation_indices: Vec<usize>,
}

pub(super) fn discovery_validation_split(
    rows: &[DecisionTraceRow],
    denied_indices: &[usize],
    allowed_indices: &[usize],
) -> Option<DiscoveryValidationSplit> {
    if denied_indices.len() < DISCOVERY_VALIDATION_MIN_CLASS_ROWS
        || allowed_indices.len() < DISCOVERY_VALIDATION_MIN_CLASS_ROWS
    {
        return None;
    }

    let (train_denied_indices, validation_denied_indices) =
        stratified_train_validation_indices(rows, denied_indices);
    let (train_allowed_indices, validation_allowed_indices) =
        stratified_train_validation_indices(rows, allowed_indices);
    if train_denied_indices.is_empty()
        || train_allowed_indices.is_empty()
        || validation_denied_indices.is_empty()
        || validation_allowed_indices.is_empty()
    {
        return None;
    }

    let mut validation_indices = validation_denied_indices;
    validation_indices.extend(validation_allowed_indices);
    validation_indices.sort_unstable();

    Some(DiscoveryValidationSplit {
        train_denied_indices,
        train_allowed_indices,
        validation_indices,
    })
}

fn stratified_train_validation_indices(
    rows: &[DecisionTraceRow],
    indices: &[usize],
) -> (Vec<usize>, Vec<usize>) {
    let mut sorted = indices.to_vec();
    sorted.sort_by_key(|index| stable_row_bucket(&rows[*index]));

    let validation_count = std::cmp::max(
        1,
        (sorted.len() * DISCOVERY_VALIDATION_FRACTION_NUMERATOR)
            / DISCOVERY_VALIDATION_FRACTION_DENOMINATOR,
    )
    .min(sorted.len().saturating_sub(1));

    let validation = sorted[..validation_count].to_vec();
    let train = sorted[validation_count..].to_vec();
    (train, validation)
}

fn stable_row_bucket(row: &DecisionTraceRow) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    row.allowed.hash(&mut hasher);
    let sorted_features = row.features.iter().collect::<BTreeMap<_, _>>();
    for (key, value) in sorted_features {
        key.hash(&mut hasher);
        hash_json_value(&mut hasher, value);
    }
    hasher.finish()
}

fn hash_json_value(hasher: &mut impl std::hash::Hasher, value: &Value) {
    use std::hash::Hash;
    match value {
        Value::Null => 0u8.hash(hasher),
        Value::Bool(b) => {
            1u8.hash(hasher);
            b.hash(hasher);
        }
        Value::Number(n) => {
            2u8.hash(hasher);
            // Use the string representation for stable hashing of numbers.
            n.to_string().hash(hasher);
        }
        Value::String(s) => {
            3u8.hash(hasher);
            s.hash(hasher);
        }
        Value::Array(arr) => {
            4u8.hash(hasher);
            arr.len().hash(hasher);
            for item in arr {
                hash_json_value(hasher, item);
            }
        }
        Value::Object(obj) => {
            5u8.hash(hasher);
            obj.len().hash(hasher);
            for (k, v) in obj {
                k.hash(hasher);
                hash_json_value(hasher, v);
            }
        }
    }
}
