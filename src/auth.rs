use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use tower_cookies::Cookies;

use crate::jwt::{Claims, Jwt};

pub struct Auth {
    pub claims: Claims,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for Auth {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|(status, _)| status)?;

        let Some(session_cookie) = cookies.get("session") else {
            return Err(StatusCode::UNAUTHORIZED);
        };

        let claims = Jwt::decode(session_cookie.value().to_string());

        Ok(Auth { claims: claims })
    }
}
