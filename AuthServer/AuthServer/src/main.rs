use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    routing::post,
    Json, Router,
};
use axum::http::header::AUTHORIZATION;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

const SECRET_KEY: &[u8] = b"change-this-to-a-highly-secure-key-in-production";

#[derive(Deserialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    key_bundle: Value, // Accepts the dynamic E2EE key bundle JSON
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Serialize)]
struct TicketResponse {
    ticket: String,
}

// 1. Shared State Definition
struct AppState {
    redis_client: redis::Client,
    db_pool: sqlx::PgPool,
}

// 2. JWT Claims Definition
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // The username
    exp: usize,  // Expiration time
}

// 3. The JWT Extractor (Middleware)
#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Look for the Authorization header
        let auth_header = parts.headers.get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.starts_with("Bearer "))
            .ok_or((StatusCode::UNAUTHORIZED, "Missing or invalid token"))?;

        let token = auth_header.trim_start_matches("Bearer ");

        // Decode and validate the JWT
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(SECRET_KEY),
            &Validation::default(),
        ).map_err(|_| (StatusCode::UNAUTHORIZED, "Token expired or invalid"))?;

        Ok(token_data.claims)
    }
}