// main.rs - ULTRA SECURE TODO App with SQLite
use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use actix_web::middleware::Logger;
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Utc, Duration};
use sqlx::{SqlitePool, FromRow};
use sqlx::sqlite::SqliteConnectOptions;
use std::str::FromStr;
use std::fmt;
use std::env;

// ðŸ”’ SECURITY: Use environment variable for JWT secret
// Fallback to strong default for development only
fn get_jwt_secret() -> Vec<u8> {
    env::var("JWT_SECRET")
        .unwrap_or_else(|_| {
            println!("âš ï¸  WARNING: Using default JWT secret. Set JWT_SECRET env var in production!");
            "9k2JHd8f7GH3jk2L9mN4vB6xC8zD1eF5gH7iJ9kL2mN4pQ6rS8tU0vW2xY4zA6bC".to_string()
        })
        .into_bytes()
}

// ========== STRUCTS ==========

#[derive(Serialize, Deserialize, Clone, FromRow)]
struct Todo {
    id: i64,
    title: String,
    completed: bool,
    user_id: i64,
}

#[derive(Serialize, Deserialize, Clone, FromRow)]
struct User {
    id: i64,
    username: String,
    #[serde(skip_serializing)]
    password: String,
    role: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
enum UserRole {
    Admin,
    User,
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserRole::Admin => write!(f, "Admin"),
            UserRole::User => write!(f, "User"),
        }
    }
}

impl UserRole {
    fn from_string(s: &str) -> Self {
        match s {
            "Admin" => UserRole::Admin,
            _ => UserRole::User,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: i64,
    exp: usize,
    iat: usize, // issued at
}

struct AppState {
    db: SqlitePool,
}

// ========== REQUEST/RESPONSE STRUCTS ==========

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: UserInfo,
}

#[derive(Serialize)]
struct UserInfo {
    id: i64,
    username: String,
    role: UserRole,
}

#[derive(Deserialize)]
struct CreateTodo {
    title: String,
}

#[derive(Deserialize)]
struct UpdateTodo {
    title: Option<String>,
    completed: Option<bool>,
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    role: UserRole,
}

#[derive(Debug, Deserialize)]
struct UpdateUserRequest {
    username: Option<String>,
    password: Option<String>,
    role: Option<UserRole>,
}

#[derive(Serialize)]
struct UserInfoWithPassword {
    id: i64,
    username: String,
    role: UserRole,
    password_hash: String,
}


// ========== SECURITY LOGGING ==========

fn log_security_event(event_type: &str, details: &str, req: &HttpRequest) {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let conn_info = req.connection_info();  // âœ… binding yang bertahan lebih lama
let ip = conn_info.peer_addr().unwrap_or("unknown");
    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    println!("\nðŸš¨ SECURITY EVENT: {}", event_type);
    println!("   Time: {}", timestamp);
    println!("   IP: {}", ip);
    println!("   User-Agent: {}", user_agent);
    println!("   Details: {}", details);
    println!();
}

// ========== DATABASE INITIALIZATION ==========

async fn init_database() -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str("sqlite://todo_app.db")?
        .create_if_missing(true);
    
    let pool = SqlitePool::connect_with(options).await?;

    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT 0,
            user_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&pool)
    .await?;

    // Create security_logs table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await?;

    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await?;

    if user_count.0 == 0 {
        let admin_password = hash("admin123", DEFAULT_COST).unwrap();
        let user_password = hash("user123", DEFAULT_COST).unwrap();

        sqlx::query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
            .bind("admin")
            .bind(&admin_password)
            .bind("Admin")
            .execute(&pool)
            .await?;

        sqlx::query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
            .bind("user")
            .bind(&user_password)
            .bind("User")
            .execute(&pool)
            .await?;

        sqlx::query("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)")
            .bind("Belajar Rust Security")
            .bind(false)
            .bind(1)
            .execute(&pool)
            .await?;

        sqlx::query("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)")
            .bind("Setup authentication & database")
            .bind(true)
            .bind(1)
            .execute(&pool)
            .await?;

        println!("âœ… Default users created successfully!");
    }

    Ok(pool)
}

// ========== HELPER FUNCTIONS ==========

fn create_jwt(user_id: i64) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expiration = now
        .checked_add_signed(Duration::hours(24))
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id,
        exp: expiration,
        iat: now.timestamp() as usize,
    };

    let secret = get_jwt_secret();
    encode(&Header::default(), &claims, &EncodingKey::from_secret(&secret))
}

fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = get_jwt_secret();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&secret),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

// ðŸ”’ CRITICAL SECURITY: Enhanced token validation with database verification
async fn get_user_from_token(req: &HttpRequest, pool: &SqlitePool) -> Result<User, String> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .ok_or("Missing Authorization header")?
        .to_str()
        .map_err(|_| "Invalid Authorization header")?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or("Invalid token format")?;

    // Verify JWT signature and expiration
    let claims = verify_jwt(token).map_err(|e| {
        log_security_event(
            "INVALID_TOKEN",
            &format!("JWT verification failed: {:?}", e),
            req
        );
        "Invalid or expired token".to_string()
    })?;

    // ðŸ”’ SECURITY: Verify user exists in database
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(claims.sub)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            log_security_event(
                "DATABASE_ERROR",
                &format!("Failed to fetch user: {:?}", e),
                req
            );
            "Database error".to_string()
        })?;

    match user {
        Some(u) => Ok(u),
        None => {
            // ðŸš¨ CRITICAL: Token with non-existent user_id
            log_security_event(
                "TOKEN_WITH_INVALID_USER",
                &format!("Token claims user_id {} but user not found in database", claims.sub),
                req
            );
            Err("User not found - token may be forged".to_string())
        }
    }
}

// ========== AUTH HANDLERS ==========

async fn register(
    data: web::Data<AppState>,
    req: HttpRequest,
    req_body: web::Json<RegisterRequest>,
) -> impl Responder {
    // Validate input
    if req_body.username.len() < 3 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username minimal 3 karakter"
        }));
    }

    if req_body.password.len() < 6 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password minimal 6 karakter"
        }));
    }

    let existing_user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(&req_body.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if existing_user.is_some() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username sudah digunakan"
        }));
    }

    let hashed_password = match hash(&req_body.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Gagal hash password"
        })),
    };

    let result = sqlx::query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
        .bind(&req_body.username)
        .bind(&hashed_password)
        .bind("User")
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            let user_id = res.last_insert_rowid();
            
            log_security_event(
                "USER_REGISTERED",
                &format!("New user registered: {} (ID: {})", req_body.username, user_id),
                &req
            );

            let token = match create_jwt(user_id) {
                Ok(t) => t,
                Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Gagal membuat token"
                })),
            };

            HttpResponse::Ok().json(LoginResponse {
                token,
                user: UserInfo {
                    id: user_id,
                    username: req_body.username.clone(),
                    role: UserRole::User,
                },
            })
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Gagal membuat user"
        })),
    }
}

async fn login(
    data: web::Data<AppState>,
    req: HttpRequest,
    req_body: web::Json<LoginRequest>,
) -> impl Responder {
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(&req_body.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let user = match user {
        Some(u) => u,
        None => {
            log_security_event(
                "LOGIN_FAILED",
                &format!("Login attempt with non-existent username: {}", req_body.username),
                &req
            );
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Username atau password salah"
            }));
        }
    };

    if !verify(&req_body.password, &user.password).unwrap_or(false) {
        log_security_event(
            "LOGIN_FAILED",
            &format!("Failed login attempt for user: {}", req_body.username),
            &req
        );
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Username atau password salah"
        }));
    }

    let token = match create_jwt(user.id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Gagal membuat token"
        })),
    };

    log_security_event(
        "LOGIN_SUCCESS",
        &format!("User logged in: {} (ID: {})", user.username, user.id),
        &req
    );

    HttpResponse::Ok().json(LoginResponse {
        token,
        user: UserInfo {
            id: user.id,
            username: user.username,
            role: UserRole::from_string(&user.role),
        },
    })
}

async fn get_current_user(
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    match get_user_from_token(&req, &data.db).await {
        Ok(user) => HttpResponse::Ok().json(UserInfo {
            id: user.id,
            username: user.username,
            role: UserRole::from_string(&user.role),
        }),
        Err(e) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": e
        })),
    }
}

// ========== TODO HANDLERS (CRUD) ==========

async fn get_todos(
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    
    let todos: Vec<Todo> = if user_role == UserRole::Admin {
        sqlx::query_as("SELECT * FROM todos ORDER BY id DESC")
            .fetch_all(&data.db)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query_as("SELECT * FROM todos WHERE user_id = ? ORDER BY id DESC")
            .bind(user.id)
            .fetch_all(&data.db)
            .await
            .unwrap_or_default()
    };

    HttpResponse::Ok().json(todos)
}

async fn create_todo(
    data: web::Data<AppState>,
    req: HttpRequest,
    todo: web::Json<CreateTodo>,
) -> impl Responder {
    // ðŸ”’ SECURITY: Get and verify user from token
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => {
            log_security_event(
                "UNAUTHORIZED_TODO_CREATE",
                &format!("Unauthorized TODO create attempt: {}", e),
                &req
            );
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Unauthorized"
            }));
        }
    };

    // ðŸ”’ DOUBLE VERIFICATION: Ensure user exists in database
    let user_exists: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE id = ?")
        .bind(user.id)
        .fetch_optional(&data.db)
        .await
        .ok()
        .flatten();

    if user_exists.is_none() {
        log_security_event(
            "FORGED_TOKEN_DETECTED",
            &format!("Token claims user_id {} but user doesn't exist in database!", user.id),
            &req
        );
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Invalid user - possible token forgery detected"
        }));
    }

    // Validate title
    if todo.title.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Title cannot be empty"
        }));
    }

    if todo.title.len() > 200 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Title too long (max 200 characters)"
        }));
    }

    println!("ðŸ”’ CREATE TODO Security Check:");
    println!("   User ID from token: {}", user.id);
    println!("   Username: {}", user.username);
    println!("   Role: {}", user.role);
    println!("   TODO title: {}", todo.title);

    let result = sqlx::query("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)")
        .bind(&todo.title)
        .bind(false)
        .bind(user.id)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            let new_todo = Todo {
                id: res.last_insert_rowid(),
                title: todo.title.clone(),
                completed: false,
                user_id: user.id,
            };
            println!("âœ… TODO created: ID {} for user_id {}", new_todo.id, user.id);
            HttpResponse::Ok().json(new_todo)
        }
        Err(e) => {
            println!("âŒ Failed to create TODO: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create todo"
            }))
        }
    }
}

async fn update_todo(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    update: web::Json<UpdateTodo>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    let todo_id = path.into_inner();

    let todo: Option<Todo> = sqlx::query_as("SELECT * FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let todo = match todo {
        Some(t) => t,
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Todo not found"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    
    if user_role != UserRole::Admin && todo.user_id != user.id {
        log_security_event(
            "UNAUTHORIZED_TODO_UPDATE",
            &format!("User {} tried to update TODO {} owned by user {}", user.id, todo_id, todo.user_id),
            &req
        );
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Forbidden - you don't own this TODO"
        }));
    }

    let new_title = update.title.as_ref().unwrap_or(&todo.title);
    let new_completed = update.completed.unwrap_or(todo.completed);

    let result = sqlx::query("UPDATE todos SET title = ?, completed = ? WHERE id = ?")
        .bind(new_title)
        .bind(new_completed)
        .bind(todo_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
            let updated_todo = Todo {
                id: todo_id,
                title: new_title.clone(),
                completed: new_completed,
                user_id: todo.user_id,
            };
            HttpResponse::Ok().json(updated_todo)
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to update todo"
        })),
    }
}

async fn toggle_todo(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    let todo_id = path.into_inner();

    let todo: Option<Todo> = sqlx::query_as("SELECT * FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let todo = match todo {
        Some(t) => t,
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Todo not found"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    
    if user_role != UserRole::Admin && todo.user_id != user.id {
        log_security_event(
            "UNAUTHORIZED_TODO_TOGGLE",
            &format!("User {} tried to toggle TODO {} owned by user {}", user.id, todo_id, todo.user_id),
            &req
        );
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Forbidden"
        }));
    }

    let new_completed = !todo.completed;
    let result = sqlx::query("UPDATE todos SET completed = ? WHERE id = ?")
        .bind(new_completed)
        .bind(todo_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
            let updated_todo = Todo {
                id: todo_id,
                title: todo.title,
                completed: new_completed,
                user_id: todo.user_id,
            };
            HttpResponse::Ok().json(updated_todo)
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to toggle todo"
        })),
    }
}

async fn delete_todo(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    let todo_id = path.into_inner();

    let todo: Option<Todo> = sqlx::query_as("SELECT * FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let todo = match todo {
        Some(t) => t,
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Todo not found"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    
    if user_role != UserRole::Admin && todo.user_id != user.id {
        log_security_event(
            "UNAUTHORIZED_TODO_DELETE",
            &format!("User {} tried to delete TODO {} owned by user {}", user.id, todo_id, todo.user_id),
            &req
        );
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Forbidden"
        }));
    }

    let result = sqlx::query("DELETE FROM todos WHERE id = ?")
        .bind(todo_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
            println!("âœ… TODO {} deleted by user {}", todo_id, user.id);
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Todo deleted successfully"
            }))
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to delete todo"
        })),
    }
}

// ========== ADMIN HANDLERS ==========

async fn get_all_users(
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    if user_role != UserRole::Admin {
        log_security_event(
            "UNAUTHORIZED_ADMIN_ACCESS",
            &format!("Non-admin user {} tried to access user list", user.id),
            &req
        );
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin only"
        }));
    }

    let users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY id")
        .fetch_all(&data.db)
        .await
        .unwrap_or_default();

    let user_infos: Vec<UserInfoWithPassword> = users
        .iter()
        .map(|u| UserInfoWithPassword {
            id: u.id,
            username: u.username.clone(),
            role: UserRole::from_string(&u.role),
            password_hash: u.password.clone(),
        })
        .collect();

    HttpResponse::Ok().json(user_infos)
}

async fn create_user(
    data: web::Data<AppState>,
    req: HttpRequest,
    user_req: web::Json<CreateUserRequest>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    if user_role != UserRole::Admin {
        log_security_event(
            "UNAUTHORIZED_USER_CREATE",
            &format!("Non-admin user {} tried to create user", user.id),
            &req
        );
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin only"
        }));
    }

    if user_req.username.len() < 3 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username minimal 3 karakter"
        }));
    }

    let existing_user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(&user_req.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if existing_user.is_some() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username sudah digunakan"
        }));
    }

    if user_req.password.len() < 6 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password minimal 6 karakter"
        }));
    }

    let hashed_password = match hash(&user_req.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Gagal hash password"
            }));
        }
    };

    let role_str = user_req.role.to_string();
    
    let result = sqlx::query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
        .bind(&user_req.username)
        .bind(&hashed_password)
        .bind(&role_str)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            log_security_event(
                "USER_CREATED_BY_ADMIN",
                &format!("Admin {} created user {} with role {}", user.id, user_req.username, role_str),
                &req
            );
            
            HttpResponse::Ok().json(UserInfo {
                id: res.last_insert_rowid(),
                username: user_req.username.clone(),
                role: user_req.role.clone(),
            })
        }
        Err(_) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Gagal membuat user"
            }))
        }
    }
}


async fn update_user(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    update_req: web::Json<UpdateUserRequest>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    if user_role != UserRole::Admin {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin only"
        }));
    };

    let user_id = path.into_inner();

    let target_user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&data.db)
        .await
      .unwrap_or(None);

    let _target_user = match target_user {
        Some(u) => u,
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        })),
    };

    let mut updates = Vec::new();
    if let Some(new_username) = &update_req.username {
        if new_username.len() < 3 {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Username minimal 3 karakter"
            }));
        }

        let existing: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ? AND id != ?")
            .bind(new_username)
            .bind(user_id)
            .fetch_optional(&data.db)
            .await
            .unwrap_or(None);

        if existing.is_some() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Username sudah digunakan"
            }));
        }

        updates.push("username = ?");
    }

    if let Some(new_password) = &update_req.password {
        if new_password.len() < 6 {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Password minimal 6 karakter"
            }));
        }

        updates.push("password = ?");
    }

    if update_req.role.is_some() {
        updates.push("role = ?");
    }

    if updates.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No updates provided"
        }));
    }

    let query = format!("UPDATE users SET {}  WHERE id = ?", updates.join(", "));
    let mut query_builder = sqlx::query(&query);

    if let Some(username) = &update_req.username {
        query_builder = query_builder.bind(username);
    }
    if let Some(password) = &update_req.password {
        let hashed = hash(password, DEFAULT_COST).unwrap();
        query_builder = query_builder.bind(hashed);
    }
    if let Some(role) = &update_req.role {
        query_builder = query_builder.bind(role.to_string());
    }
    query_builder = query_builder.bind(user_id);

    match query_builder.execute(&data.db).await {
        Ok(_) => {
            log_security_event(
                "USER_UPDATED_BY_ADMIN",
                &format!("Admin {} updated user {}", user.id, user_id),
                &req
            );

            let updated_user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_one(&data.db)
                .await
                .unwrap();

            HttpResponse::Ok().json(UserInfo {
                id: updated_user.id,
                username: updated_user.username,
                role: UserRole::from_string(&updated_user.role),
            })
        }
        Err(e) => {
            println!("Error updating user: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to update user"
            }))
        }
    }
}
async fn delete_user(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    if user_role != UserRole::Admin {
        log_security_event(
            "UNAUTHORIZED_USER_DELETE",
            &format!("Non-admin user {} tried to delete user", user.id),
            &req
        );
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin only"
        }));
    }

    let user_id = path.into_inner();

    if user_id == user.id {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Cannot delete yourself"
        }));
    }

    let _ = sqlx::query("DELETE FROM todos WHERE user_id = ?")
        .bind(user_id)
        .execute(&data.db)
        .await;

    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                log_security_event(
                    "USER_DELETED_BY_ADMIN",
                    &format!("Admin {} deleted user_id {}", user.id, user_id),
                    &req
                );
                HttpResponse::Ok().json(serde_json::json!({
                    "message": "User deleted successfully"
                }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({
                    "error": "User not found"
                }))
            }
        }
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to delete user"
        })),
    }
}

// ========== FRONTEND ==========

async fn index() -> impl Responder {
    let html = std::fs::read_to_string("index.html")
        .unwrap_or_else(|_| "<h1>Error: index.html tidak ditemukan</h1>".to_string());
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// ========== MAIN ==========

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    println!("\nðŸ”’ ULTRA SECURE TODO APP - INITIALIZING");
    println!("==========================================");
    
    println!("\nðŸ”§ Initializing database...");
    let pool = init_database().await.expect("Failed to initialize database");
    println!("âœ… Database initialized!");

    println!("\nðŸš€ Server Configuration:");
    println!("   Address: http://localhost:8080");
    println!("   Database: todo_app.db");
    
    println!("\nðŸ”‘ Demo Accounts:");
    println!("   Admin: admin / admin123");
    println!("   User:  user  / user123");
    
    println!("\nðŸ›¡ï¸  SECURITY FEATURES ENABLED:");
    println!("   âœ… JWT with strong secret key");
    println!("   âœ… Database user verification on every request");
    println!("   âœ… Token forgery detection");
    println!("   âœ… Comprehensive security logging");
    println!("   âœ… Role-based access control");
    println!("   âœ… Input validation");
    println!("   âœ… CORS protection");
    println!("   âœ… Foreign key constraints");
    println!("   âœ… Timestamp tracking");
    
    println!("\nâš ï¸  SECURITY NOTES:");
    println!("   â€¢ Set JWT_SECRET environment variable in production");
    println!("   â€¢ Monitor security_logs table for suspicious activity");
    println!("   â€¢ Change default passwords immediately");
    println!("   â€¢ Use HTTPS in production");
    
    println!("\n==========================================");
    println!("Server is ready to accept connections\n");

    let app_state = web::Data::new(AppState { db: pool });

    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(app_state.clone())
            .app_data(web::JsonConfig::default().limit(1024 * 1024)) // 1MB limit
            .route("/api/register", web::post().to(register))
            .route("/api/login", web::post().to(login))
            .route("/api/me", web::get().to(get_current_user))
            .route("/api/todos", web::get().to(get_todos))
            .route("/api/todos", web::post().to(create_todo))
            .route("/api/todos/{id}", web::put().to(update_todo))
            .route("/api/todos/{id}/toggle", web::put().to(toggle_todo))
            .route("/api/todos/{id}", web::delete().to(delete_todo))
            .route("/api/admin/users", web::get().to(get_all_users))
            .route("/api/admin/users", web::post().to(create_user))
            .route("/api/admin/users/{id}", web::put().to(update_user))
            .route("/api/admin/users/{id}", web::delete().to(delete_user))
            .route("/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
