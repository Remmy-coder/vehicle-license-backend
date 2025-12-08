use axum::{Json, extract::State, http::StatusCode};
use nanoid::nanoid;

use crate::{
    auth::{
        auth_extractor::{ApiContext, AuthUser},
        utils::hash_password,
    },
    error::{AppError, AppResult, ErrorResponse},
    models::user::{CreateUserWithoutPassRequest, User},
    repositories::user_repository::UserRepository,
};

#[utoipa::path(
    post,
    path = "/api/users",
    request_body = CreateUserWithoutPassRequest,
    responses(
        (status = 201, description = "User created successfully", body = User,
            example = json!({
                "id": "LaeC612OVPyQgROf_L_xP",
                "email": "john.doe@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "role": "applicant",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T10:30:00Z"
            })
        ),
        (status = 400, description = "Validation error", body = ErrorResponse,
            examples(
                ("Email exists" = (value = json!({"error": "Email already exists"}))),
                ("Password too short" = (value = json!({"error": "Password must be at least 8 characters"})))
            )
        ),
        (status = 401, description = "Not authenticated", body = ErrorResponse,
            example = json!({"error": "Authentication required"})
        ),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse,
            example = json!({"error": "Admin access required"})
        ),
        (status = 500, description = "Internal server error", body = ErrorResponse,
            example = json!({"error": "Database error: connection failed"})
        ),
    ),
    tag = "User Management",
    summary = "Create a new user",
    description = "Creates a new user account, generates a new password and emails it to the user. Only accessible by administrators. The password is hashed using Argon2 before storage.",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn create_user_without_pass(
    _auth_user: AuthUser,
    State(ctx): State<ApiContext>,
    Json(data): Json<CreateUserWithoutPassRequest>,
) -> AppResult<(StatusCode, Json<User>)> {
    // NOTE: Impl Authorization

    if UserRepository::email_exists(&ctx.db, &data.email).await? {
        return Err(AppError::Validation("Email already exists".to_string()));
    }

    // NOTE: Email user generated pass
    let generated_pass = nanoid!(20);

    let password_hash = hash_password(&generated_pass).await?;

    let user = UserRepository::create_user(
        &ctx.db,
        &data.email,
        &password_hash,
        &data.first_name,
        &data.last_name,
        data.role,
    )
    .await?;

    Ok((StatusCode::CREATED, Json(user)))
}
