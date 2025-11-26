use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use time::OffsetDateTime;

#[derive(Debug, Serialize, Deserialize, Type, Clone, PartialEq, Eq)]
#[sqlx(type_name = "text")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Applicant,
    Officer,
    Admin,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub role: Role,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}
