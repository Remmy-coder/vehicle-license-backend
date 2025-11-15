use sqlx::Error as SqlxError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] SqlxError),

    #[error("Configuration error: {0}")]
    Config(#[from] std::env::VarError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unexpected error: {0}")]
    Other(String),
}

pub type AppResult<T> = Result<T, AppError>;

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Other(err.to_string())
    }
}
