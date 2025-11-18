use crate::{
    error::AppResult,
    models::user::{Role, User},
};
use nanoid::nanoid;
use sqlx::PgPool;

pub struct UserRepository;

impl UserRepository {
    pub async fn create_user(
        pool: &PgPool,
        email: &str,
        password_hash: &str,
        first_name: &str,
        last_name: &str,
        role: Role,
    ) -> AppResult<User> {
        let id = nanoid!();
        let record = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, email, password_hash, first_name, last_name, role)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            "#,
            id,
            email,
            password_hash,
            first_name,
            last_name,
            role as Role
        )
        .fetch_one(pool)
        .await?;
        Ok(record)
    }

    pub async fn get_user_by_id(pool: &PgPool, id: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            FROM users
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(pool)
        .await?;
        Ok(user)
    }

    pub async fn get_user_by_email(pool: &PgPool, email: &str) -> AppResult<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(pool)
        .await?;
        Ok(user)
    }

    pub async fn get_user_with_password(
        pool: &PgPool,
        email: &str,
    ) -> AppResult<Option<(User, String)>> {
        let record = sqlx::query!(
            r#"
            SELECT 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                password_hash,
                created_at as "created_at!", 
                updated_at as "updated_at!"
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(pool)
        .await?;

        Ok(record.map(|r| {
            (
                User {
                    id: r.id,
                    email: r.email,
                    first_name: r.first_name,
                    last_name: r.last_name,
                    role: r.role,
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                },
                r.password_hash,
            )
        }))
    }

    pub async fn get_all_users(pool: &PgPool, limit: i64, offset: i64) -> AppResult<Vec<User>> {
        let users = sqlx::query_as!(
            User,
            r#"
            SELECT 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            FROM users
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(pool)
        .await?;
        Ok(users)
    }

    pub async fn get_users_by_role(pool: &PgPool, role: Role) -> AppResult<Vec<User>> {
        let users = sqlx::query_as!(
            User,
            r#"
            SELECT 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            FROM users
            WHERE role = $1
            ORDER BY created_at DESC
            "#,
            role as Role
        )
        .fetch_all(pool)
        .await?;
        Ok(users)
    }

    pub async fn update_user(
        pool: &PgPool,
        id: &str,
        first_name: &str,
        last_name: &str,
    ) -> AppResult<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET first_name = $2, last_name = $3, updated_at = NOW()
            WHERE id = $1
            RETURNING 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            "#,
            id,
            first_name,
            last_name
        )
        .fetch_one(pool)
        .await?;
        Ok(user)
    }

    pub async fn update_email(pool: &PgPool, id: &str, email: &str) -> AppResult<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET email = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            "#,
            id,
            email
        )
        .fetch_one(pool)
        .await?;
        Ok(user)
    }

    pub async fn update_password(pool: &PgPool, id: &str, password_hash: &str) -> AppResult<()> {
        sqlx::query!(
            r#"
            UPDATE users
            SET password_hash = $2, updated_at = NOW()
            WHERE id = $1
            "#,
            id,
            password_hash
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn update_role(pool: &PgPool, id: &str, role: Role) -> AppResult<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET role = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING 
                id, 
                email, 
                first_name, 
                last_name, 
                role as "role: Role", 
                created_at as "created_at!", 
                updated_at as "updated_at!"
            "#,
            id,
            role as Role
        )
        .fetch_one(pool)
        .await?;
        Ok(user)
    }

    pub async fn delete_user(pool: &PgPool, id: &str) -> AppResult<()> {
        sqlx::query!(
            r#"
            DELETE FROM users
            WHERE id = $1
            "#,
            id
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn count_users(pool: &PgPool) -> AppResult<i64> {
        let result = sqlx::query!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM users
            "#
        )
        .fetch_one(pool)
        .await?;
        Ok(result.count)
    }

    pub async fn email_exists(pool: &PgPool, email: &str) -> AppResult<bool> {
        let result = sqlx::query!(
            r#"
            SELECT EXISTS(SELECT 1 FROM users WHERE email = $1) as "exists!"
            "#,
            email
        )
        .fetch_one(pool)
        .await?;
        Ok(result.exists)
    }
}
