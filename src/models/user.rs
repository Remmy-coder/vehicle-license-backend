use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use time::OffsetDateTime;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Type, Clone, PartialEq, Eq, ToSchema)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[sqlx(rename = "applicant")]
    Applicant,
    #[sqlx(rename = "officer")]
    Officer,
    #[sqlx(rename = "admin")]
    Admin,
}

#[derive(Debug, Serialize, Deserialize, FromRow, ToSchema)]
pub struct User {
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

    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = "date-time", example = "2024-01-15T10:30:00Z")]
    pub created_at: OffsetDateTime,

    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = "date-time", example = "2024-01-20T14:45:00Z")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserWithoutPassRequest {
    #[schema(example = "john.doe@example.com")]
    pub email: String,

    #[schema(example = "John")]
    pub first_name: String,

    #[schema(example = "Doe")]
    pub last_name: String,

    #[schema(example = "applicant")]
    pub role: Role,
}
