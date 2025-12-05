use crate::models::user::Role;
use serde::{Deserialize, Serialize};
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
