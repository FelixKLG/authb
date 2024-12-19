use crate::jwt::Jwt;
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

mod auth;
mod jwt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;

    let router = Router::new()
        .route("/login", post(login))
        .route("/whoami", get(who_am_i))
        .layer(CookieManagerLayer::new());

    axum::serve(listener, router).await?;

    Ok(())
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    #[serde(rename = "password")]
    _password: String,
}

async fn login(cookies: Cookies, Json(credentials): Json<LoginRequest>) -> StatusCode {
    let token = Jwt::encode(credentials.username);

    cookies.add(Cookie::new("session", token));

    StatusCode::OK
}

#[derive(Serialize)]
struct WhoAmIResponse {
    pub user_id: String,
}

async fn who_am_i(auth: auth::Auth) -> Result<Json<WhoAmIResponse>, StatusCode> {
    let user_id = auth.claims;
    let response = WhoAmIResponse { user_id: user_id.sub };

    Ok(Json(response))
}
