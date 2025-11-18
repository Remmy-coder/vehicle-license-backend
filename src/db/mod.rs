use crate::error::AppResult;
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use std::time::Duration;

pub async fn init_pool_default(database_url: &str) -> AppResult<Pool<Postgres>> {
    init_pool(database_url, 10).await
}

pub async fn init_pool(database_url: &str, max_connections: u32) -> AppResult<Pool<Postgres>> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(2)
        .max_lifetime(Duration::from_secs(1800))
        .idle_timeout(Some(Duration::from_secs(600)))
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await?;

    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pool)
        .await?;

    Ok(pool)
}
