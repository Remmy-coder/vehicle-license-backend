use crate::{
    auth::auth_extractor::ApiContext,
    controllers::auth_controller::{change_password, get_current_user, login, logout, register},
};
use axum::{
    Router,
    routing::{get, post},
};

pub fn auth_routes() -> Router<ApiContext> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(get_current_user))
        .route("/change-password", post(change_password))
}
