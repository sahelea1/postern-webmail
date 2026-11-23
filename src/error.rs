use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Not signed in")]
    Unauthorized,
    #[error("The address or password is not correct")]
    BadCredentials,
    #[error("This address cannot sign in here")]
    UnknownDomain,
    #[error("{0}")]
    BadRequest(String),
    #[error("Not found")]
    NotFound,
    #[error("Request blocked")]
    Forbidden,
    #[error("Too many attempts. Try again in a few minutes")]
    RateLimited,
    #[error("The mail server reported a problem: {0}")]
    Upstream(String),
    #[error("The mail server cannot be reached")]
    Unreachable(String),
    #[error("Internal error")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn bad(msg: impl Into<String>) -> Self {
        Error::BadRequest(msg.into())
    }
    pub fn upstream(msg: impl std::fmt::Display) -> Self {
        Error::Upstream(clip(&msg.to_string()))
    }
    fn code(&self) -> (&'static str, StatusCode) {
        match self {
            Error::Unauthorized => ("unauthorized", StatusCode::UNAUTHORIZED),
            Error::BadCredentials => ("bad_credentials", StatusCode::UNAUTHORIZED),
            Error::UnknownDomain => ("unknown_domain", StatusCode::FORBIDDEN),
            Error::BadRequest(_) => ("bad_request", StatusCode::BAD_REQUEST),
            Error::NotFound => ("not_found", StatusCode::NOT_FOUND),
            Error::Forbidden => ("forbidden", StatusCode::FORBIDDEN),
            Error::RateLimited => ("rate_limited", StatusCode::TOO_MANY_REQUESTS),
            Error::Upstream(_) => ("upstream", StatusCode::BAD_GATEWAY),
            Error::Unreachable(_) => ("unreachable", StatusCode::BAD_GATEWAY),
            Error::Internal(_) => ("internal", StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}

/// Keeps upstream error text short and on one line before it reaches a client or a log.
fn clip(s: &str) -> String {
    let one_line: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect();
    one_line.trim().to_string()
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (code, status) = self.code();
        match &self {
            Error::Internal(detail) => tracing::error!(%detail, "internal error"),
            Error::Unreachable(detail) => tracing::warn!(%detail, "mail server unreachable"),
            Error::Upstream(detail) => tracing::debug!(%detail, "mail server error"),
            _ => {}
        }
        let body = serde_json::json!({ "error": code, "message": self.to_string() });
        (status, Json(body)).into_response()
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Unreachable(clip(&e.to_string()))
    }
}

impl From<async_imap::error::Error> for Error {
    fn from(e: async_imap::error::Error) -> Self {
        use async_imap::error::Error as E;
        match e {
            E::Io(e) => Error::Unreachable(clip(&e.to_string())),
            E::ConnectionLost => Error::Unreachable("connection lost".into()),
            E::No(m) | E::Bad(m) => Error::Upstream(clip(&m)),
            other => Error::Upstream(clip(&other.to_string())),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        // Never include the URL: it could carry identifiers.
        let e = e.without_url();
        if e.is_connect() || e.is_timeout() {
            Error::Unreachable(clip(&e.to_string()))
        } else {
            Error::Upstream(clip(&e.to_string()))
        }
    }
}

impl From<axum::extract::multipart::MultipartError> for Error {
    fn from(e: axum::extract::multipart::MultipartError) -> Self {
        Error::BadRequest(clip(&e.to_string()))
    }
}
