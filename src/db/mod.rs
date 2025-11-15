use crate::error::{AppError, AppResult};
use sqlx::{Pool, Postgres, postgres::PgPoolOptions};
use std::time::Duration;

pub async fn init_pool(database_url: &str, max_connections: u32) -> AppResult<Pool<Postgres>> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(1)
        .max_lifetime(Duration::from_secs(5))
        .idle_timeout(Some(Duration::from_secs(300)))
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await?;

    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pool)
        .await?;

    Ok(pool)
}

