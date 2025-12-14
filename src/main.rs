// main.rs - Aplikasi TODO dengan database SQLite (MAXIMUM SECURITY)
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

// 🔒 SECURITY FIX: HAPUS user_id dari request, server yang tentukan!
#[derive(Deserialize)]
struct CreateTodo {
    title: String,
    // user_id DIHAPUS! Tidak boleh ada di request dari client
}

#[derive(Deserialize)]
struct UpdateTodo {
    title: Option<String>,
    completed: Option<bool>,
    // user_id TIDAK BOLEH diubah!
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    role: UserRole,
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
            role TEXT NOT NULL
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
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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

fn create_jwt(user_id: i64) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id,
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

    let claims = verify_jwt(token).map_err(|_| "Invalid or expired token".to_string())?;

    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(claims.sub)
        .fetch_optional(pool)
        .await
        .map_err(|_| "Database error".to_string())?;

    user.ok_or("User not found".to_string())
}

// ========== AUTH HANDLERS ==========

async fn register(
    data: web::Data<AppState>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
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

    let hashed_password = match hash(&req.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Gagal hash password"
        })),
    };

    let result = sqlx::query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
        .bind(&req.username)
        .bind(&hashed_password)
        .bind("User")
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            let user_id = res.last_insert_rowid();
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
                    username: req.username.clone(),
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

    let token = match create_jwt(user.id) {
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
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let user_role = UserRole::from_string(&user.role);
    
    // 🔒 SECURITY: Admin lihat semua dengan info username, User hanya miliknya
    let todos: Vec<Todo> = if user_role == UserRole::Admin {
        sqlx::query_as("SELECT * FROM todos ORDER BY id DESC")
            .fetch_all(&data.db)
            .await
            .unwrap_or_default()
    } else {
        // User biasa HANYA bisa lihat TODO miliknya sendiri
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
    // 🔒 CRITICAL SECURITY: Ambil user dari token, BUKAN dari request body!
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Unauthorized"
        })),
    };

    // 🔒 SECURITY: user_id SELALU diambil dari token yang terverifikasi
    // TIDAK ADA cara untuk user mengubah user_id lewat request
    let target_user_id = user.id;

    println!("🔒 CREATE TODO Security Check:");
    println!("   User ID from token: {}", user.id);
    println!("   Username: {}", user.username);
    println!("   Role: {}", user.role);
    println!("   TODO will be created for user_id: {}", target_user_id);

    let result = sqlx::query("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)")
        .bind(&todo.title)
        .bind(false)
        .bind(target_user_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            let new_todo = Todo {
                id: res.last_insert_rowid(),
                title: todo.title.clone(),
                completed: false,
                user_id: target_user_id,
            };
            println!("✅ TODO created successfully with ID: {} for user_id: {}", new_todo.id, target_user_id);
            HttpResponse::Ok().json(new_todo)
        }
        Err(e) => {
            println!("❌ Failed to create TODO: {:?}", e);
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
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let todo_id = path.into_inner();

    // 🔒 SECURITY: Ambil TODO dari database untuk cek ownership
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
    
    // 🔒 SECURITY: Cek ownership - User hanya bisa edit miliknya
    if user_role != UserRole::Admin && todo.user_id != user.id {
        println!("❌ FORBIDDEN: User {} tried to edit TODO {} owned by user {}", 
                 user.id, todo_id, todo.user_id);
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Anda tidak memiliki akses ke TODO ini"
        }));
    }

    let new_title = update.title.as_ref().unwrap_or(&todo.title);
    let new_completed = update.completed.unwrap_or(todo.completed);

    // 🔒 SECURITY: user_id TIDAK BISA diubah, tetap gunakan yang lama
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
                user_id: todo.user_id, // user_id tetap tidak berubah
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
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Todo not found"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    
    // 🔒 SECURITY: Cek ownership
    if user_role != UserRole::Admin && todo.user_id != user.id {
        println!("❌ FORBIDDEN: User {} tried to toggle TODO {} owned by user {}", 
                 user.id, todo_id, todo.user_id);
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Anda tidak memiliki akses ke TODO ini"
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
        None => return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Todo not found"
        })),
    };

    let user_role = UserRole::from_string(&user.role);
    
    // 🔒 SECURITY: Cek ownership
    if user_role != UserRole::Admin && todo.user_id != user.id {
        println!("❌ FORBIDDEN: User {} tried to delete TODO {} owned by user {}", 
                 user.id, todo_id, todo.user_id);
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Anda tidak memiliki akses ke TODO ini"
        }));
    }

    let result = sqlx::query("DELETE FROM todos WHERE id = ?")
        .bind(todo_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
            println!("✅ TODO {} deleted by user {}", todo_id, user.id);
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
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let user_role = UserRole::from_string(&user.role);
    if user_role != UserRole::Admin {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin only"
        }));
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
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let user_role = UserRole::from_string(&user.role);
    if user_role != UserRole::Admin {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin only"
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

async fn delete_user(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<i64>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let user_role = UserRole::from_string(&user.role);
    if user_role != UserRole::Admin {
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

    println!("🔧 Initializing database...");
    let pool = init_database().await.expect("Failed to initialize database");
    println!("✅ Database initialized!");

    println!("\n🚀 Server berjalan di http://localhost:8080");
    println!("🔑 Admin: username=admin, password=admin123");
    println!("👤 User: username=user, password=user123");
    println!("💾 Database: todo_app.db");
    println!("\n🔒 MAXIMUM SECURITY FEATURES:");
    println!("   ✅ Role validation 100% server-side");
    println!("   ✅ User CANNOT specify user_id in requests");
    println!("   ✅ user_id ALWAYS taken from verified JWT token");
    println!("   ✅ Users can ONLY create/edit/delete their own TODOs");
    println!("   ✅ Admin has full access to all TODOs");
    println!("   ✅ All requests logged for security audit\n");

    let app_state = web::Data::new(AppState { db: pool });

    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(app_state.clone())
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
            .route("/api/admin/users/{id}", web::delete().to(delete_user))
            .route("/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}