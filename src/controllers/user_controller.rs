use serde::Deserialize;
use utoipa::ToSchema;

use crate::models::user::Role;

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
