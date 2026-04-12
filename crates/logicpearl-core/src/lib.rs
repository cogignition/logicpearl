// SPDX-License-Identifier: MIT
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

/// Convenience alias for results returned by LogicPearl operations.
pub type Result<T> = std::result::Result<T, LogicPearlError>;

/// Errors produced by LogicPearl operations.
#[derive(Debug, Error)]
pub enum LogicPearlError {
    /// A freeform error message.
    #[error("{0}")]
    Message(String),
    /// An I/O error propagated from the standard library.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A JSON serialization or deserialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A CSV parsing error.
    #[error(transparent)]
    Csv(#[from] csv::Error),
}

impl LogicPearlError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

/// Renders an artifact value into a human-readable string.
pub trait ArtifactRenderer<T> {
    /// Produce a textual representation of `value`.
    fn render(&self, value: &T) -> Result<String>;
}

/// Variable-width bitmask that tracks which rules matched during evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleMask {
    words: Vec<u64>,
}

impl RuleMask {
    /// Create an all-zeros mask (no rules matched).
    pub fn zero() -> Self {
        Self::default()
    }

    /// Returns `true` when no bits are set.
    pub fn is_zero(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Set the bit at position `bit`.
    pub fn set_bit(&mut self, bit: u32) {
        let word_index = bit as usize / 64;
        let bit_index = bit % 64;
        if self.words.len() <= word_index {
            self.words.resize(word_index + 1, 0);
        }
        self.words[word_index] |= 1_u64 << bit_index;
    }

    /// Returns `true` if the bit at position `bit` is set.
    pub fn test_bit(&self, bit: u32) -> bool {
        let word_index = bit as usize / 64;
        let bit_index = bit % 64;
        self.words
            .get(word_index)
            .map(|word| (word & (1_u64 << bit_index)) != 0)
            .unwrap_or(false)
    }

    /// If the mask fits in a single `u64`, return it; otherwise `None`.
    pub fn as_u64(&self) -> Option<u64> {
        match self.trimmed_words() {
            [] => Some(0),
            [single] => Some(*single),
            _ => None,
        }
    }

    /// Serialize this mask to a JSON number (single word) or array (multi-word).
    pub fn to_json_value(&self) -> Value {
        if let Some(single) = self.as_u64() {
            Value::Number(single.into())
        } else {
            Value::Array(
                self.trimmed_words()
                    .iter()
                    .map(|word| Value::Number((*word).into()))
                    .collect(),
            )
        }
    }

    /// Deserialize a mask from a JSON number or array of numbers.
    pub fn from_json_value(value: &Value) -> Result<Self> {
        match value {
            Value::Number(number) => number.as_u64().map(Self::from).ok_or_else(|| {
                LogicPearlError::message("bitmask number must be an unsigned integer")
            }),
            Value::Array(items) => {
                let mut words = Vec::with_capacity(items.len());
                for item in items {
                    let word = item.as_u64().ok_or_else(|| {
                        LogicPearlError::message("bitmask array items must be unsigned integers")
                    })?;
                    words.push(word);
                }
                Ok(Self::from_words(words))
            }
            _ => Err(LogicPearlError::message(
                "bitmask must be a JSON number or an array of JSON numbers",
            )),
        }
    }

    /// Build a mask from a raw vector of 64-bit words.
    pub fn from_words(words: Vec<u64>) -> Self {
        let mut mask = Self { words };
        mask.trim_trailing_zero_words();
        mask
    }

    fn trimmed_words(&self) -> &[u64] {
        let mut end = self.words.len();
        while end > 0 && self.words[end - 1] == 0 {
            end -= 1;
        }
        &self.words[..end]
    }

    fn trim_trailing_zero_words(&mut self) {
        while self.words.last().copied() == Some(0) {
            self.words.pop();
        }
    }
}

impl From<u64> for RuleMask {
    fn from(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self { words: vec![value] }
        }
    }
}

impl std::fmt::Display for RuleMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(single) = self.as_u64() {
            write!(f, "{single}")
        } else {
            write!(f, "{}", self.to_json_value())
        }
    }
}

impl Serialize for RuleMask {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(single) = self.as_u64() {
            serializer.serialize_u64(single)
        } else {
            self.trimmed_words().serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for RuleMask {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::from_json_value(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::RuleMask;
    use serde_json::json;

    #[test]
    fn rule_mask_round_trips_small_and_wide_forms() {
        let mut wide = RuleMask::zero();
        wide.set_bit(0);
        wide.set_bit(72);
        assert_eq!(wide.to_json_value(), json!([1, 256]));
        let parsed: RuleMask = serde_json::from_value(json!([1, 256])).unwrap();
        assert_eq!(parsed, wide);

        let small: RuleMask = serde_json::from_value(json!(7)).unwrap();
        assert_eq!(small.as_u64(), Some(7));
    }
}
