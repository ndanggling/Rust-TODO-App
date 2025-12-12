// main.rs - Aplikasi TODO dengan database SQLite
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

const JWT_SECRET: &[u8] = b"your-secret-key-change-in-production";

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
    username: String,
    role: UserRole,
    exp: usize,
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

// ========== DATABASE INITIALIZATION ==========

async fn init_database() -> Result<SqlitePool, sqlx::Error> {
    // Gunakan SqliteConnectOptions untuk kontrol lebih baik
    let options = SqliteConnectOptions::from_str("sqlite://todo_app.db")?
        .create_if_missing(true); // Otomatis buat file jika belum ada
    
    let pool = SqlitePool::connect_with(options).await?;

    // Enable foreign keys
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&pool)
        .await?;

    // Create users table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    // Create todos table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT 0,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&pool)
    .await?;

    // Check if default users exist
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await?;

    // Insert default users if none exist
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

        // Insert sample todos
        sqlx::query("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)")
            .bind("Belajar Rust")
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

        println!("✅ Default users created successfully!");
    }

    Ok(pool)
}

// ========== HELPER FUNCTIONS ==========

fn create_jwt(user: &User) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id,
        username: user.username.clone(),
        role: UserRole::from_string(&user.role),
        exp: expiration,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
}

fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

fn get_user_from_token(req: &HttpRequest) -> Result<Claims, String> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .ok_or("Missing Authorization header")?
        .to_str()
        .map_err(|_| "Invalid Authorization header")?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or("Invalid token format")?;

    verify_jwt(token).map_err(|_| "Invalid or expired token".to_string())
}

// ========== AUTH HANDLERS ==========

async fn register(
    data: web::Data<AppState>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    // Check if username exists
    let existing_user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if existing_user.is_some() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username sudah digunakan"
        }));
    }

    // Hash password
    let hashed_password = match hash(&req.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Gagal hash password"
        })),
    };

    // Insert new user
    let result = sqlx::query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
        .bind(&req.username)
        .bind(&hashed_password)
        .bind("User")
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            let new_user = User {
                id: res.last_insert_rowid(),
                username: req.username.clone(),
                password: hashed_password,
                role: "User".to_string(),
            };

            let token = match create_jwt(&new_user) {
                Ok(t) => t,
                Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Gagal membuat token"
                })),
            };

            HttpResponse::Ok().json(LoginResponse {
                token,
                user: UserInfo {
                    id: new_user.id,
                    username: new_user.username,
                    role: UserRole::from_string(&new_user.role),
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
    req: web::Json<LoginRequest>,
) -> impl Responder {
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let user = match user {
        Some(u) => u,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Username atau password salah"
        })),
    };

    if !verify(&req.password, &user.password).unwrap_or(false) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Username atau password salah"
        }));
    }

    let token = match create_jwt(&user) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Gagal membuat token"
        })),
    };

    HttpResponse::Ok().json(LoginResponse {
        token,
        user: UserInfo {
            id: user.id,
            username: user.username,
            role: UserRole::from_string(&user.role),
        },
    })
}

async fn get_current_user(req: HttpRequest) -> impl Responder {
    match get_user_from_token(&req) {
        Ok(claims) => HttpResponse::Ok().json(UserInfo {
            id: claims.sub,
            username: claims.username,
            role: claims.role,
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
    let claims = match get_user_from_token(&req) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let todos: Vec<Todo> = if claims.role == UserRole::Admin {
        sqlx::query_as("SELECT * FROM todos ORDER BY id DESC")
            .fetch_all(&data.db)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query_as("SELECT * FROM todos WHERE user_id = ? ORDER BY id DESC")
            .bind(claims.sub)
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
    let claims = match get_user_from_token(&req) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let result = sqlx::query("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)")
        .bind(&todo.title)
        .bind(false)
        .bind(claims.sub)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            let new_todo = Todo {
                id: res.last_insert_rowid(),
                title: todo.title.clone(),
                completed: false,
                user_id: claims.sub,
            };
            HttpResponse::Ok().json(new_todo)
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to create todo"),
    }
}

async fn update_todo(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
    update: web::Json<UpdateTodo>,
) -> impl Responder {
    let claims = match get_user_from_token(&req) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let todo_id = path.into_inner();

    let todo: Option<Todo> = sqlx::query_as("SELECT * FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let todo = match todo {
        Some(t) => t,
        None => return HttpResponse::NotFound().body("Todo not found"),
    };

    if claims.role != UserRole::Admin && todo.user_id != claims.sub {
        return HttpResponse::Forbidden().body("Forbidden");
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
        Err(_) => HttpResponse::InternalServerError().body("Failed to update todo"),
    }
}

async fn toggle_todo(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> impl Responder {
    let claims = match get_user_from_token(&req) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let todo_id = path.into_inner();

    let todo: Option<Todo> = sqlx::query_as("SELECT * FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let todo = match todo {
        Some(t) => t,
        None => return HttpResponse::NotFound().body("Todo not found"),
    };

    if claims.role != UserRole::Admin && todo.user_id != claims.sub {
        return HttpResponse::Forbidden().body("Forbidden");
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
        Err(_) => HttpResponse::InternalServerError().body("Failed to toggle todo"),
    }
}

async fn delete_todo(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> impl Responder {
    let claims = match get_user_from_token(&req) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let todo_id = path.into_inner();

    let todo: Option<Todo> = sqlx::query_as("SELECT * FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let todo = match todo {
        Some(t) => t,
        None => return HttpResponse::NotFound().body("Todo not found"),
    };

    if claims.role != UserRole::Admin && todo.user_id != claims.sub {
        return HttpResponse::Forbidden().body("Forbidden");
    }

    let result = sqlx::query("DELETE FROM todos WHERE id = ?")
        .bind(todo_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().body("Todo deleted"),
        Err(_) => HttpResponse::InternalServerError().body("Failed to delete todo"),
    }
}

// ========== ADMIN HANDLERS ==========

async fn get_all_users(
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let claims = match get_user_from_token(&req) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    if claims.role != UserRole::Admin {
        return HttpResponse::Forbidden().body("Admin only");
    }

    let users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY id")
        .fetch_all(&data.db)
        .await
        .unwrap_or_default();

    let user_infos: Vec<UserInfo> = users
        .iter()
        .map(|u| UserInfo {
            id: u.id,
            username: u.username.clone(),
            role: UserRole::from_string(&u.role),
        })
        .collect();

    HttpResponse::Ok().json(user_infos)
}

async fn create_user(
    data: web::Data<AppState>,
    req: HttpRequest,
    user_req: web::Json<CreateUserRequest>,
) -> impl Responder {
    let claims = match get_user_from_token(&req) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    if claims.role != UserRole::Admin {
        return HttpResponse::Forbidden().body("Admin only");
    }

    // ===== DEBUG: Print received data =====
    println!("=== CREATE USER REQUEST ===");
    println!("Username: {}", user_req.username);
    println!("Password length: {}", user_req.password.len());
    println!("Role: {:?}", user_req.role);
    println!("========================");

    let existing_user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(&user_req.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if existing_user.is_some() {
        println!("❌ ERROR: Username already exists");  // Debug log
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username sudah digunakan"
        }));
    }

    if user_req.password.len() < 6 {
        println!("❌ ERROR: Password too short");  // Debug log
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Password minimal 6 karakter"
        }));
    }

    let hashed_password = match hash(&user_req.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            println!("❌ ERROR: Failed to hash password: {:?}", e);  // Debug log
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Gagal hash password"
            }));
        }
    };

    let role_str = user_req.role.to_string();
    println!("✅ Inserting user into database...");  // Debug log
    
    let result = sqlx::query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
        .bind(&user_req.username)
        .bind(&hashed_password)
        .bind(&role_str)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            println!("✅ User created successfully with ID: {}", res.last_insert_rowid());
            HttpResponse::Ok().json(UserInfo {
                id: res.last_insert_rowid(),
                username: user_req.username.clone(),
                role: user_req.role.clone(),
            })
        }
        Err(e) => {
            println!("❌ ERROR: Database insert failed: {:?}", e);  // Debug log
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Gagal membuat user"
            }))
        }
    }
}

async fn delete_user(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> impl Responder {
    let claims = match get_user_from_token(&req) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    if claims.role != UserRole::Admin {
        return HttpResponse::Forbidden().body("Admin only");
    }

    let user_id = path.into_inner();

    if user_id == claims.sub {
        return HttpResponse::BadRequest().body("Cannot delete yourself");
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
                HttpResponse::Ok().body("User deleted")
            } else {
                HttpResponse::NotFound().body("User not found")
            }
        }
        Err(_) => HttpResponse::InternalServerError().body("Failed to delete user"),
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

    println!("🔧 Initializing database...");
    let pool = init_database().await.expect("Failed to initialize database");
    println!("✅ Database initialized!");

    println!("🚀 Server berjalan di http://localhost:8080");
    println!("🔑 Admin: username=admin, password=admin123");
    println!("👤 User: username=user, password=user123");
    println!("💾 Database: todo_app.db");

    let app_state = web::Data::new(AppState { db: pool });

    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(app_state.clone())
            // Auth routes
            .route("/api/register", web::post().to(register))
            .route("/api/login", web::post().to(login))
            .route("/api/me", web::get().to(get_current_user))
            // TODO routes
            .route("/api/todos", web::get().to(get_todos))
            .route("/api/todos", web::post().to(create_todo))
            .route("/api/todos/{id}", web::put().to(update_todo))
            .route("/api/todos/{id}/toggle", web::put().to(toggle_todo))
            .route("/api/todos/{id}", web::delete().to(delete_todo))
            // Admin routes
            .route("/api/admin/users", web::get().to(get_all_users))
            .route("/api/admin/users", web::post().to(create_user))
            .route("/api/admin/users/{id}", web::delete().to(delete_user))
            // Frontend
            .route("/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}