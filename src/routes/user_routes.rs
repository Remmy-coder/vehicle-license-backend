use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    auth::auth_extractor::ApiContext,
    controllers::user_controller::{create_user_without_pass, get_all_users},
};

pub fn user_routes() -> Router<ApiContext> {
    Router::new()
        .route("/create-user-without-pass", post(create_user_without_pass))
        .route("/retrieve", get(get_all_users))
}
