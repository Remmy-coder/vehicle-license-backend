use axum::{
    Json,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use csv::Writer;
use nanoid::nanoid;
use time::format_description::well_known::Rfc3339;

use crate::{
    auth::{
        auth_extractor::{ApiContext, AuthUser},
        utils::hash_password,
    },
    error::{AppError, AppResult, ErrorResponse},
    models::user::{
        CreateUserWithoutPassRequest, GetUsersQuery, PaginatedResponse, PaginatedUsersResponse,
        PaginationInfo, Role, User, UserQueryParams,
    },
    repositories::user_repository::UserRepository,
};

#[utoipa::path(
    post,
    path = "/api/users/create-user-without-pass",
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

#[utoipa::path(
    get,
    path = "/api/users/retrieve",
    params(
        ("page" = Option<i64>, Query, description = "Page number of users to return (default: 1)"),
        ("limit" = Option<i64>, Query, description = "Maximum number of users to return (default: 50)"),
        ("offset" = Option<i64>, Query, description = "Number of users to skip (default: 0)"),
        ("role" = Option<Role>, Query, description = "Filter users by role"),
        ("fields" = Option<String>, Query, description = "Search term to filter users by email, first_name, or last_name (case-insensitive partial match)"),
        ("export" = Option<String>, Query, description = "Export format: 'csv' or 'json'")
    ),
    responses(
        (status = 200, description = "List of users retrieved successfully", body = PaginatedUsersResponse,
            example = json!({
                "data": [
                    {
                        "id": "LaeC612OVPyQgROf_L_xP",
                        "email": "john.doe@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "role": "applicant",
                        "created_at": "2024-01-15T10:30:00Z",
                        "updated_at": "2024-01-15T10:30:00Z"
                    }
                ],
                "pagination": {
                    "current_page": 1,
                    "per_page": 50,
                    "total_items": 100,
                    "total_pages": 2,
                    "has_next": true,
                    "has_prev": false
                }
            })
        ),
        (status = 401, description = "Not authenticated", body = ErrorResponse, 
            example = json!({"error": "Authentication required"})
        ),
        (status = 500, description = "Internal server error", body = ErrorResponse, 
            example = json!({"error": "Database error: connection failed"})
        ),
    ),
    tag = "User Management",
    summary = "Get all users with filtering and export",
    description = "Retrieves a paginated list of users with optional search and role filtering. Supports CSV and JSON export formats. The 'fields' parameter searches across email, first_name, and last_name columns.",
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn get_all_users(
    _auth_user: AuthUser,
    State(ctx): State<ApiContext>,
    Query(query): Query<GetUsersQuery>,
) -> AppResult<Response> {
    let params = UserQueryParams {
        page: query.page,
        limit: query.limit,
        offset: query.offset,
        role: query.role,
        fields: query.fields.clone(),
    };

    let users = UserRepository::get_all_users_filtered(&ctx.db, &params).await?;
    let total_items = UserRepository::count_users_filtered(&ctx.db, &params).await?;

    match query.export.as_deref() {
        Some("csv") => {
            let csv_data = generate_csv(&users)?;
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/csv"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"users.csv\"",
                    ),
                ],
                csv_data,
            )
                .into_response())
        }
        Some("json") => {
            let json_data = serde_json::to_string_pretty(&users)
                .map_err(|e| AppError::Other(format!("JSON serialization error: {}", e)))?;
            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"users.json\"",
                    ),
                ],
                json_data,
            )
                .into_response())
        }
        _ => {
            let current_page = params.page.unwrap_or(1).max(1);
            let per_page = params.get_limit();
            let total_pages = (total_items as f64 / per_page as f64).ceil() as i64;
            let has_next = current_page < total_pages;
            let has_prev = current_page > 1;

            let pagination = PaginationInfo {
                current_page,
                per_page,
                total_items,
                total_pages,
                has_next,
                has_prev,
            };

            let response = PaginatedResponse {
                data: users,
                pagination,
            };

            Ok((StatusCode::OK, Json(response)).into_response())
        }
    }
}

fn generate_csv(users: &[User]) -> AppResult<String> {
    let mut wtr = Writer::from_writer(vec![]);

    // Write headers
    wtr.write_record(&["id", "email", "first_name", "last_name", "role", "created_at", "updated_at"])
        .map_err(|e| AppError::Other(format!("CSV write error: {}", e)))?;

    // Write rows
    for user in users {
        let row = vec![
            user.id.clone(),
            user.email.clone(),
            user.first_name.clone(),
            user.last_name.clone(),
            format!("{:?}", user.role),
            user.created_at
                .format(&Rfc3339)
                .map_err(|e| AppError::Other(format!("Date format error: {}", e)))?,
            user.updated_at
                .format(&Rfc3339)
                .map_err(|e| AppError::Other(format!("Date format error: {}", e)))?,
        ];
        wtr.write_record(&row)
            .map_err(|e| AppError::Other(format!("CSV write error: {}", e)))?;
    }

    wtr.flush()
        .map_err(|e| AppError::Other(format!("CSV flush error: {}", e)))?;

    String::from_utf8(
        wtr.into_inner()
            .map_err(|e| AppError::Other(format!("CSV conversion error: {}", e)))?,
    )
    .map_err(|e| AppError::Other(format!("UTF-8 conversion error: {}", e)))
}
