use axum::{
    Json, Router, extract::{FromRequestParts}, http::{StatusCode, request::Parts}, routing::post
};
use axum::http::header::AUTHORIZATION;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::sync::OnceLock;
use std::future::Future;
use uuid::Uuid;

mod types;
mod login_handler;
mod register_handler;

use types::{AppState, Claims, TicketResponse};
use login_handler::login_handler;
use register_handler::register_handler;

// openssl rand -base64 32
pub static SECRET_KEY: OnceLock<String> = OnceLock::new();

// 3. The JWT Extractor (Middleware)
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let auth_header = parts.headers.get(AUTHORIZATION).cloned();

        async move {
            let auth_header = auth_header
                .and_then(|value| value.to_str().ok().map(str::to_owned))
                .filter(|value| value.starts_with("Bearer "))
                .ok_or((StatusCode::UNAUTHORIZED, "Missing or invalid token"))?;

            let token = auth_header.trim_start_matches("Bearer ");

            let token_data = decode::<Claims>(
                token,
                &DecodingKey::from_secret(SECRET_KEY.get().expect("SECRET_KEY must be initialized").as_bytes()),
                &Validation::default(),
            ).map_err(|_| (StatusCode::UNAUTHORIZED, "Token expired or invalid"))?;

            Ok(token_data.claims)
        }
    }
}

pub async fn ws_ticket_handler(
    claims: Claims
) -> Result<Json<TicketResponse>, (StatusCode, String)> {

    let short_expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::minutes(5))
        .unwrap()
        .timestamp() as usize;

    let ticket_claims = Claims {
        sub: claims.sub.clone(),
        exp: short_expiration,
    };

    let ticket_jwt = encode(
        &Header::default(),
        &ticket_claims,
        &EncodingKey::from_secret(SECRET_KEY.get().expect("SECRET_KEY must be initialized").as_bytes())
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create ticket: {}", e)))?;

    Ok(Json(TicketResponse { ticket: ticket_jwt }))
}

#[tokio::main]
async fn main() {
    // Check for environment variable, otherwise generate an ephemeral random key
    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| {
            println!("WARNING: JWT_SECRET not found in environment. Generating a temporary random key. All users will be logged out on server restart.");
            format!("{}{}", Uuid::new_v4(), Uuid::new_v4())
        });
    SECRET_KEY.set(secret).expect("Failed to set SECRET_KEY");

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let db_pool = PgPoolOptions::new()
        .max_connections(20) // Increased connection pool for production
        .connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    let state = Arc::new(AppState {
        db_pool,
    });

    let app = Router::new()
        .route("/api/auth/register", post(register_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/auth/ws_ticket", post(ws_ticket_handler))
        .with_state(state);

    // Bind to 0.0.0.0 so Azure can route external traffic to this container/app
    let port = std::env::var("PORT").unwrap_or_else(|_| "8001".to_string());
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap();

    println!("Auth Server running on http://{}", bind_addr);
    axum::serve(listener, app).await.unwrap();

}