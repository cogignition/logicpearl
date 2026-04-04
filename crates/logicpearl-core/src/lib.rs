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
