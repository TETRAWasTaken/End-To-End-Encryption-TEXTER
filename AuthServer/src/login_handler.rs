use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use axum::{
    Json, extract::State, http::StatusCode
};
use jsonwebtoken::{encode, EncodingKey, Header};
use std::sync::Arc;

use crate::types::{AppState, AuthRequest, Claims, TokenResponse};
use crate::SECRET_KEY;

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AuthRequest>
) -> Result<Json<TokenResponse>, (StatusCode, String)> {

    let row: (String,) = sqlx::query_as("SELECT  password_hash FROM User_Info WHERE user_id = $1")
        .bind(&payload.username)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "User Not Found".to_string()))?;

    let password_hash = row.0;

    let parsed_hash = PasswordHash::new(&password_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Hash Parse Error".to_string()))?;

    Argon2::default().verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid Password".to_string()))?;

    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(7))
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        sub: payload.username,
        exp: expiration
    };

    let secret = SECRET_KEY.get().expect("SECRET_KEY must be initialized").as_bytes();
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Token Generation Error".to_string()))?;

    Ok(Json(TokenResponse { access_token: token }))
}