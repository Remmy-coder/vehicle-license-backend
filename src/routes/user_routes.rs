use axum::{Router, routing::post};

use crate::{
    auth::auth_extractor::ApiContext, controllers::user_controller::create_user_without_pass,
};

pub fn user_routes() -> Router<ApiContext> {
    Router::new().route("/create-user-without-pass", post(create_user_without_pass))
}
