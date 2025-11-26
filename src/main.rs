mod auth;
mod controllers;
mod db;
mod error;
mod models;
mod repositories;
mod routes;

use crate::{auth::auth_extractor::ApiContext, db::init_pool_default};
use axum::Router;
use dotenvy::dotenv;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());

    let db_pool = init_pool_default(&database_url).await?;

    let ctx = ApiContext {
        db: db_pool,
        jwt_secret,
    };

    let app = Router::new()
        .nest("/api/auth", routes::auth_routes::auth_routes())
        .with_state(ctx);

    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Server running on http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}
