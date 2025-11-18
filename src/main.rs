mod db;
mod error;
mod models;
mod repositories;

use crate::{db::init_pool_default, error::AppResult};
use dotenvy::dotenv;
use std::env;

#[tokio::main]
async fn main() -> AppResult<()> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")?;
    let pool = init_pool_default(&database_url).await?;

    println!("Database pool initialized successfully");
    Ok(())
}
