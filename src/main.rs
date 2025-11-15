mod db;
mod error;

use crate::error::{AppError, AppResult};
use db::init_pool;
use dotenvy::dotenv;
use std::env;

#[tokio::main]
async fn main() -> AppResult<()> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")?;
    let pool = init_pool(&database_url, 10).await?;

    println!("✅ Database pool initialized successfully");
    Ok(())
}
