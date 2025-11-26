use crate::{error::AppError, models::user::Role, repositories::user_repository::UserRepository};
use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use axum_extra::{
    TypedHeader,
    extract::CookieJar,
    headers::{Authorization, authorization::Bearer},
};
use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha384;
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
}

#[derive(Debug, Clone)]
pub struct MaybeAuthUser(pub Option<AuthUser>);

#[derive(Debug, Serialize, Deserialize)]
struct AuthUserClaims {
    user_id: String,
    exp: i64,
}

#[derive(Clone)]
pub struct ApiContext {
    pub db: sqlx::PgPool,
    pub jwt_secret: String,
}

impl AuthUser {
    pub fn from_token(ctx: &ApiContext, token: &str) -> Result<Self, AppError> {
        let hmac = Hmac::<Sha384>::new_from_slice(ctx.jwt_secret.as_bytes())
            .map_err(|e| AppError::Auth(format!("Invalid HMAC key: {}", e)))?;

        let claims: AuthUserClaims = token.verify_with_key(&hmac).map_err(|e| {
            tracing::debug!("JWT failed to verify: {}", e);
            AppError::Auth("Invalid token".to_string())
        })?;

        if claims.exp < OffsetDateTime::now_utc().unix_timestamp() {
            tracing::debug!("Token expired");
            return Err(AppError::Auth("Token expired".to_string()));
        }

        Ok(Self {
            user_id: claims.user_id,
        })
    }

    pub fn to_jwt(&self, ctx: &ApiContext) -> Result<String, AppError> {
        use jwt::SignWithKey;
        use time::Duration;

        let hmac = Hmac::<Sha384>::new_from_slice(ctx.jwt_secret.as_bytes())
            .map_err(|e| AppError::Auth(format!("Invalid HMAC key: {}", e)))?;

        let claims = AuthUserClaims {
            user_id: self.user_id.clone(),
            exp: (OffsetDateTime::now_utc() + Duration::weeks(2)).unix_timestamp(),
        };

        claims
            .sign_with_key(&hmac)
            .map_err(|e| AppError::Auth(format!("Failed to sign JWT: {}", e)))
    }
}

impl MaybeAuthUser {
    pub fn user_id(&self) -> Option<String> {
        self.0.as_ref().map(|auth_user| auth_user.user_id.clone())
    }

    pub fn into_inner(self) -> Option<AuthUser> {
        self.0
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    ApiContext: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match MaybeAuthUser::from_request_parts(parts, state).await? {
            MaybeAuthUser(Some(auth_user)) => Ok(auth_user),
            MaybeAuthUser(None) => Err(AppError::Auth("Not authenticated".to_string())),
        }
    }
}

impl<S> FromRequestParts<S> for MaybeAuthUser
where
    S: Send + Sync,
    ApiContext: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ctx: ApiContext = ApiContext::from_ref(state);

        if let Some(TypedHeader(Authorization(bearer))) = parts
            .extract::<Option<TypedHeader<Authorization<Bearer>>>>()
            .await
            .ok()
            .flatten()
        {
            let user = AuthUser::from_token(&ctx, bearer.token())?;
            return Ok(Self(Some(user)));
        }

        let Ok(jar) = parts.extract::<CookieJar>().await;

        if let Some(cookie) = jar.get("jwt") {
            let user = AuthUser::from_token(&ctx, cookie.value())?;
            return Ok(Self(Some(user)));
        }

        Ok(Self(None))
    }
}

#[derive(Debug, Clone)]
pub struct RequireRole {
    pub roles: Vec<Role>,
}

impl RequireRole {
    pub fn new(roles: Vec<crate::models::user::Role>) -> Self {
        Self { roles }
    }

    pub fn admin() -> Self {
        Self::new(vec![crate::models::user::Role::Admin])
    }

    pub fn officer() -> Self {
        Self::new(vec![
            crate::models::user::Role::Officer,
            crate::models::user::Role::Admin,
        ])
    }

    pub fn any() -> Self {
        Self::new(vec![
            crate::models::user::Role::Applicant,
            crate::models::user::Role::Officer,
            crate::models::user::Role::Admin,
        ])
    }

    pub async fn check(&self, ctx: &ApiContext, user_id: &str) -> Result<(), AppError> {
        let user = UserRepository::get_user_by_id(&ctx.db, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if !self.roles.contains(&user.role) {
            return Err(AppError::Auth("Insufficient permissions".to_string()));
        }

        Ok(())
    }
}
