use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
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

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unexpected error: {0}")]
    Other(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Other(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        let body = Json(json!({
            "error": message
        }));

        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
