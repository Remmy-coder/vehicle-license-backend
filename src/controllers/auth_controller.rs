use crate::{
    auth::auth_extractor::{ApiContext, AuthUser},
    error::{AppError, AppResult, ErrorResponse},
    models::user::Role,
    repositories::user_repository::UserRepository,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{Json, extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use time::Duration;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    #[schema(example = "john.doe@example.com")]
    pub email: String,

    #[schema(example = "SecurePass123!", min_length = 8)]
    pub password: String,

    #[schema(example = "John")]
    pub first_name: String,

    #[schema(example = "Doe")]
    pub last_name: String,

    #[serde(default = "default_role")]
    #[schema(example = "applicant")]
    pub role: Role,
}

fn default_role() -> Role {
    Role::Applicant
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    #[schema(example = "john.doe@example.com")]
    pub email: String,

    #[schema(example = "SecurePass123!")]
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    #[schema(example = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")]
    pub token: String,

    pub user: UserInfo,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfo {
    #[schema(example = "LaeC612OVPyQgROf_L_xP")]
    pub id: String,

    #[schema(example = "john.doe@example.com")]
    pub email: String,

    #[schema(example = "John")]
    pub first_name: String,

    #[schema(example = "Doe")]
    pub last_name: String,

    #[schema(example = "applicant")]
    pub role: Role,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    #[schema(example = "OldPass123!")]
    pub current_password: String,

    #[schema(example = "NewSecurePass456!", min_length = 8)]
    pub new_password: String,
}

#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User successfully registered", body = AuthResponse,
            example = json!({
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "john.doe@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "role": "user"
                }
            })
        ),
        (status = 400, description = "Validation error - Password too short or invalid data", body = ErrorResponse,
            example = json!({
                "error": "Password must be at least 8 characters"
            })
        ),
        (status = 400, description = "Email already exists", body = ErrorResponse,
            example = json!({
                "error": "Email already exists"
            })
        ),
        (status = 500, description = "Internal server error", body = ErrorResponse,
            example = json!({
                "error": "Database error: connection failed"
            })
        ),
    ),
    tag = "Authentication",
    summary = "Register a new user",
    description = "Creates a new user account with the provided credentials. Password must be at least 8 characters. Returns a JWT token for immediate authentication."
)]
pub async fn register(
    State(ctx): State<ApiContext>,
    Json(data): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<AuthResponse>)> {
    if UserRepository::email_exists(&ctx.db, &data.email).await? {
        return Err(AppError::Validation("Email already exists".to_string()));
    }

    if data.password.len() < 8 {
        return Err(AppError::Validation(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    let password_hash = hash_password(&data.password).await?;

    let user = UserRepository::create_user(
        &ctx.db,
        &data.email,
        &password_hash,
        &data.first_name,
        &data.last_name,
        data.role,
    )
    .await?;

    let auth_user = AuthUser {
        user_id: user.id.clone(),
    };
    let token = auth_user.to_jwt(&ctx)?;

    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            token,
            user: UserInfo {
                id: user.id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                role: user.role,
            },
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse,
            example = json!({
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "john.doe@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "role": "user"
                }
            })
        ),
        (status = 401, description = "Invalid credentials", body = ErrorResponse,
            example = json!({
                "error": "Invalid email or password"
            })
        ),
        (status = 500, description = "Internal server error", body = ErrorResponse,
            example = json!({
                "error": "Database error: connection failed"
            })
        ),
    ),
    tag = "Authentication",
    summary = "Authenticate a user",
    description = "Authenticates a user with email and password. Returns a JWT token in the response body and sets an HTTP-only secure cookie for session management. The cookie expires after 2 weeks."
)]
pub async fn login(
    State(ctx): State<ApiContext>,
    Json(data): Json<LoginRequest>,
) -> AppResult<(CookieJar, Json<AuthResponse>)> {
    let (user, password_hash) = UserRepository::get_user_with_password(&ctx.db, &data.email)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid email or password".to_string()))?;

    verify_password(&data.password, &password_hash).await?;

    let auth_user = AuthUser {
        user_id: user.id.clone(),
    };
    let token = auth_user.to_jwt(&ctx)?;

    let cookie = Cookie::build(("jwt", token.clone()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::weeks(2))
        .path("/")
        .build();

    let jar = CookieJar::new().add(cookie);

    Ok((
        jar,
        Json(AuthResponse {
            token,
            user: UserInfo {
                id: user.id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                role: user.role,
            },
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/auth/logout",
    responses(
        (status = 200, description = "Successfully logged out - JWT cookie removed"),
        (status = 500, description = "Internal server error", body = ErrorResponse,
            example = json!({"error": "Failed to clear session"})
        ),
    ),
    tag = "Authentication",
    summary = "Logout current user",
    description = "Logs out the current user by removing the JWT authentication cookie. The cookie is set to expire immediately."
)]
pub async fn logout(jar: CookieJar) -> AppResult<CookieJar> {
    let cookie = Cookie::build("jwt")
        .path("/")
        .max_age(Duration::seconds(0))
        .build();

    Ok(jar.remove(cookie))
}

#[utoipa::path(
    get,
    path = "/api/auth/me",
    responses(
        (status = 200, description = "Current user information", body = UserInfo,
            example = json!({
                "id": "LaeC612OVPyQgROf_L_xP",
                "email": "john.doe@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "role": "applicant"
            })
        ),
        (status = 401, description = "Not authenticated", body = ErrorResponse,
            example = json!({"error": "Authentication required"})
        ),
        (status = 404, description = "User not found", body = ErrorResponse,
            example = json!({"error": "User not found"})
        ),
        (status = 500, description = "Internal server error", body = ErrorResponse,
            example = json!({"error": "Database error: connection failed"})
        ),
    ),
    tag = "Authentication",
    summary = "Get current user information",
    description = "Returns the profile information of the currently authenticated user. Requires a valid JWT token in the Authorization header or JWT cookie.",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_current_user(
    auth_user: AuthUser,
    State(ctx): State<ApiContext>,
) -> AppResult<Json<UserInfo>> {
    let user = UserRepository::get_user_by_id(&ctx.db, &auth_user.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(UserInfo {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/change-password",
    request_body = ChangePasswordRequest,
    responses(
        (status = 204, description = "Password successfully changed"),
        (status = 400, description = "Validation error", body = ErrorResponse,
            example = json!({"error": "Password must be at least 8 characters"})
        ),
        (status = 401, description = "Authentication failed", body = ErrorResponse,
            examples(
                ("Not authenticated" = (value = json!({"error": "Authentication required"}))),
                ("Wrong password" = (value = json!({"error": "Invalid email or password"})))
            )
        ),
        (status = 404, description = "User not found", body = ErrorResponse,
            example = json!({"error": "User not found"})
        ),
        (status = 500, description = "Internal server error", body = ErrorResponse,
            example = json!({"error": "Database error: connection failed"})
        ),
    ),
    tag = "Authentication",
    summary = "Change user password",
    description = "Changes the password for the currently authenticated user. Requires the current password for verification. The new password must be at least 8 characters and will be hashed using Argon2 before storage.",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn change_password(
    auth_user: AuthUser,
    State(ctx): State<ApiContext>,
    Json(data): Json<ChangePasswordRequest>,
) -> AppResult<StatusCode> {
    let user = UserRepository::get_user_by_id(&ctx.db, &auth_user.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let (_, current_hash) = UserRepository::get_user_with_password(&ctx.db, &user.email)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    verify_password(&data.current_password, &current_hash).await?;

    if data.new_password.len() < 8 {
        return Err(AppError::Validation(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    let new_hash = hash_password(&data.new_password).await?;

    UserRepository::update_password(&ctx.db, &auth_user.user_id, &new_hash).await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn hash_password(password: &str) -> AppResult<String> {
    let password = password.to_string();

    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| AppError::Auth(format!("Failed to hash password: {}", e)))
    })
    .await
    .map_err(|e| AppError::Other(format!("Task join error: {}", e)))?
}

async fn verify_password(password: &str, password_hash: &str) -> AppResult<()> {
    let password = password.to_string();
    let password_hash = password_hash.to_string();

    tokio::task::spawn_blocking(move || {
        let parsed_hash = PasswordHash::new(&password_hash)
            .map_err(|e| AppError::Auth(format!("Invalid password hash: {}", e)))?;

        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AppError::Auth("Invalid email or password".to_string()))
    })
    .await
    .map_err(|e| AppError::Other(format!("Task join error: {}", e)))?
}
