use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error("not found")]
    NotFound,
    #[error("authentication required")]
    Unauthorized,
    #[error("administrator required")]
    Forbidden,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Internal(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Invalid(_) | Self::Json(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, self.to_string())
            }
            Self::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            Self::Database(e)
                if e.as_database_error()
                    .is_some_and(|e| e.is_unique_violation()) =>
            {
                (StatusCode::CONFLICT, "version conflict".into())
            }
            _ => {
                tracing::error!("catalog request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        let mut response = (status, Json(json!({"error": message}))).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert("www-authenticate", "Bearer".parse().unwrap());
        }
        response
    }
}

pub fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}
