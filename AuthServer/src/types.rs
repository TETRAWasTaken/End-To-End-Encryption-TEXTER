use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub key_bundle: Value, // Accepts the dynamic E2EE key bundle JSON
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
}

#[derive(Serialize)]
pub struct TicketResponse {
    pub ticket: String,
}

// 1. Shared State Definition
pub struct AppState {
    pub db_pool: sqlx::PgPool,
}

// 2. JWT Claims Definition
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // The username
    pub exp: usize,  // Expiration time
}