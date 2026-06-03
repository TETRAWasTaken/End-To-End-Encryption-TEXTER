use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    Json, extract::State, http::StatusCode
};
use serde_json::Value;
use std::sync::Arc;

use crate::types::{AppState, RegisterRequest};

fn required_bundle_field<'a>(bundle: &'a serde_json::Map<String, Value>, field: &str) -> Result<&'a str, String> {
    bundle
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Missing or invalid key bundle field: {field}"))
}

pub async fn register_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bundle_object = payload
        .key_bundle
        .as_object()
        .ok_or((StatusCode::BAD_REQUEST, "key_bundle must be a JSON object".to_string()))?;

    let identity_key = required_bundle_field(bundle_object, "identity_key")
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let identity_key_dh = required_bundle_field(bundle_object, "identity_key_dh")
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let signed_pre_key = required_bundle_field(bundle_object, "signed_pre_key")
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let signature = required_bundle_field(bundle_object, "signature")
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let one_time_pre_keys = bundle_object
        .get("one_time_pre_keys")
        .and_then(Value::as_object)
        .ok_or((StatusCode::BAD_REQUEST, "Missing or invalid key bundle field: one_time_pre_keys".to_string()))?;

    let existing_user = sqlx::query("SELECT user_id FROM User_Info WHERE user_id = $1")
        .bind(&payload.username)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if existing_user.is_some() {
        return Err((StatusCode::CONFLICT, "User Already Exists".to_string()));
    }

    let salt = SaltString::generate(&mut rand_core::OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(payload.password.as_bytes(), &salt)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Hashing Failed".to_string()))?
        .to_string();

    let mut tx = state.db_pool.begin().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Transaction Failed".to_string()))?;

    sqlx::query("INSERT INTO User_info (user_id, password_hash) values ($1, $2)")
        .bind(&payload.username)
        .bind(&password_hash)
        .execute(tx.as_mut())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let time_stamp_creation = chrono::Utc::now();

    sqlx::query(
        r#"
        INSERT INTO identity_key (user_id, identity_key, identity_key_dh, time_stamp_creation)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id)
        DO UPDATE SET
            identity_key = EXCLUDED.identity_key,
            identity_key_dh = EXCLUDED.identity_key_dh,
            time_stamp_creation = EXCLUDED.time_stamp_creation
        "#,
    )
    .bind(&payload.username)
    .bind(identity_key)
    .bind(identity_key_dh)
    .bind(time_stamp_creation)
    .execute(tx.as_mut())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query("DELETE FROM signed_key WHERE user_id = $1")
        .bind(&payload.username)
        .execute(tx.as_mut())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query(
        "INSERT INTO signed_key (user_id, signed_pre_key, signature, time_stamp_creation) VALUES ($1, $2, $3, $4)",
    )
    .bind(&payload.username)
    .bind(signed_pre_key)
    .bind(signature)
    .bind(time_stamp_creation)
    .execute(tx.as_mut())
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query("DELETE FROM onetime_pre_key WHERE user_id = $1")
        .bind(&payload.username)
        .execute(tx.as_mut())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    for (key_id, key_value) in one_time_pre_keys {
        let normalized_key_id = key_id
            .parse::<i64>()
            .map_err(|_| (StatusCode::BAD_REQUEST, format!("Invalid one-time key id: {key_id}")))?;
        let one_time_key = key_value
            .as_str()
            .ok_or((StatusCode::BAD_REQUEST, format!("Invalid one-time key value for id: {key_id}")))?;

        sqlx::query(
            "INSERT INTO onetime_pre_key (user_id, key_id, one_time_key, is_used, time_stamp_creation) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&payload.username)
        .bind(normalized_key_id)
        .bind(one_time_key)
        .bind(false)
        .bind(time_stamp_creation)
        .execute(tx.as_mut())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    tx.commit().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Transaction Failed".to_string()))?;

    Ok(StatusCode::CREATED)
}