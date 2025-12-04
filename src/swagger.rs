use utoipa::OpenApi;

use crate::{
    controllers::auth_controller::{
        __path_change_password, __path_get_current_user, __path_login, __path_logout,
        __path_register, AuthResponse, ChangePasswordRequest, LoginRequest, RegisterRequest,
        UserInfo,
    },
    error::ErrorResponse,
};

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

#[derive(OpenApi)]
#[openapi(
    paths(
        login,
        register,
        get_current_user,
        change_password,
        logout
    ),
    components(
        schemas(
            LoginRequest,
            RegisterRequest,
            AuthResponse,
            UserInfo,
            ChangePasswordRequest,
            ErrorResponse
        )
    ),
    tags(
        (name = "Authentication", description = "User authentication and registration endpoints"),
    ),
    modifiers(&SecurityAddon),
    info(
        title = "Vehicle License System API",
        version = "1.0.0",
        description = "API for managing vehicle licenses and payments",
        contact(
            name = "R C O D R",
            email = "remmy.ro@gmail.com"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers(
        (url = "http://localhost:4000", description = "Local development server"),
        // (url = "https://api.vehiclelicense.com", description = "Production server")
    )
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Enter your JWT token in the format: Bearer <token>"))
                        .build(),
                ),
            )
        }
    }
}
