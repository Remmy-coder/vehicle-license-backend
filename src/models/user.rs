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

#[derive(Debug, Clone, Deserialize)]
pub struct UserQueryParams {
    pub page: Option<i64>,

    pub limit: Option<i64>,

    pub offset: Option<i64>,

    pub role: Option<Role>,

    pub fields: Option<String>,
}

impl UserQueryParams {
    pub fn get_limit(&self) -> i64 {
        self.limit.unwrap_or(50).min(100)
    }

    pub fn get_offset(&self) -> i64 {
        let page = self.page.unwrap_or(1).max(1);
        let per_page = self.get_limit();
        (page - 1) * per_page
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: PaginationInfo,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaginationInfo {
    pub current_page: i64,
    pub per_page: i64,
    pub total_items: i64,
    pub total_pages: i64,
    pub has_next: bool,
    pub has_prev: bool,
}

pub type PaginatedUsersResponse = PaginatedResponse<User>;

#[derive(Debug, Serialize)]
pub struct PartialUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<OffsetDateTime>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct GetUsersQuery {
    pub page: Option<i64>,

    pub limit: Option<i64>,

    pub offset: Option<i64>,

    pub role: Option<Role>,

    pub fields: Option<String>,

    pub export: Option<String>,
}
