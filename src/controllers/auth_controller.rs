use crate::{
    auth::auth_extractor::{ApiContext, AuthUser},
    error::{AppError, AppResult},
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

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub last_name: String,
    #[serde(default = "default_role")]
    pub role: Role,
}

fn default_role() -> Role {
    Role::Applicant
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub role: Role,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

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

pub async fn logout(jar: CookieJar) -> AppResult<CookieJar> {
    let cookie = Cookie::build("jwt")
        .path("/")
        .max_age(Duration::seconds(0))
        .build();

    Ok(jar.remove(cookie))
}

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
