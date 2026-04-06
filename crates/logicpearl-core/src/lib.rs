use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, LogicPearlError>;

#[derive(Debug, Error)]
pub enum LogicPearlError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Csv(#[from] csv::Error),
}

impl LogicPearlError {
    pub fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

pub trait ArtifactRenderer<T> {
    fn render(&self, value: &T) -> Result<String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleMask {
    words: Vec<u64>,
}

impl RuleMask {
    pub fn zero() -> Self {
        Self::default()
    }

    pub fn is_zero(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    pub fn set_bit(&mut self, bit: u32) {
        let word_index = bit as usize / 64;
        let bit_index = bit % 64;
        if self.words.len() <= word_index {
            self.words.resize(word_index + 1, 0);
        }
        self.words[word_index] |= 1_u64 << bit_index;
    }

    pub fn test_bit(&self, bit: u32) -> bool {
        let word_index = bit as usize / 64;
        let bit_index = bit % 64;
        self.words
            .get(word_index)
            .map(|word| (word & (1_u64 << bit_index)) != 0)
            .unwrap_or(false)
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self.trimmed_words() {
            [] => Some(0),
            [single] => Some(*single),
            _ => None,
        }
    }

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
