// main.rs - ULTRA SECURE TODO App with SQLite
use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest};
use actix_web::http::{header, Method};
use actix_web::cookie::{Cookie, SameSite, time::Duration as CookieDuration};
use actix_web::middleware::Logger;
use actix_cors::Cors;
use actix_files::NamedFile; // Added for static file serving
use actix_governor::{Governor, GovernorConfigBuilder};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use bcrypt::{hash, verify, DEFAULT_COST};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce // Or `Aes128Gcm`
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Digest}; // Added for IP hashing
use chrono::{Utc, Duration};
use sqlx::{SqlitePool, FromRow};
use sqlx::sqlite::SqliteConnectOptions;
use std::str::FromStr;
use std::fmt;
use dotenv::dotenv; // Added dotenv
use log::{info, warn, error}; // Added structured logging

// 🔒 SECURITY: Use environment variable for JWT secret
// Fallback removed to prevent insecure defaults in production
fn get_jwt_secret() -> Result<Vec<u8>, std::io::Error> {
    std::env::var("JWT_SECRET")
        .map(|s| s.into_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "JWT_SECRET not set"))
}

// Encryption Helpers
fn get_encryption_key() -> Key<Aes256Gcm> {
    let key_bytes = b"01234567890123456789012345678901"; // 32 bytes for Aes256
    // Ideally Read from ENV: ENCRYPTION_KEY
    // let key_str = std::env::var("ENCRYPTION_KEY").expect("ENCRYPTION_KEY must be set");
    // decode hex or use raw bytes
    *Key::<Aes256Gcm>::from_slice(key_bytes)
}

fn encrypt_string(plaintext: &str) -> String {
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).expect("Encryption failure");
    
    // Format: nonce + ciphertext (Base64 encoded)
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    BASE64.encode(combined)
}

fn decrypt_string(encrypted_base64: &str) -> Option<String> {
    let combined = BASE64.decode(encrypted_base64).ok()?;
    if combined.len() < 12 { return None; } // Nonce is 12 bytes

    let (nonce_bytes, ciphertext_bytes) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let key = get_encryption_key();
    let cipher = Aes256Gcm::new(&key);
    
    let plaintext = cipher.decrypt(nonce, ciphertext_bytes).ok()?;
    String::from_utf8(plaintext).ok()
}

// ========== STATIC FILE HANDLER ==========
async fn index() -> impl Responder {
    NamedFile::open("index.html")
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
    aud: String,  // Audience
    iss: String,  // Issuer
    jti: String,  // JWT ID
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


#[derive(Deserialize)]
struct PaginationParams {
    page: Option<i64>,
    limit: Option<i64>,
}

fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() < 12 { return Err("Password must be at least 12 characters"); }
    if !password.chars().any(|c| c.is_lowercase()) { return Err("Password must contain lowercase"); }
    if !password.chars().any(|c| c.is_uppercase()) { return Err("Password must contain uppercase"); }
    if !password.chars().any(|c| c.is_numeric()) { return Err("Password must contain number"); }
    
    // Simple blacklist
    let common = ["password", "123456", "admin123", "qwerty", "user123"];
    if common.iter().any(|&w| password.to_lowercase().contains(w)) {
        return Err("Password is too common/weak");
    }
    Ok(())
}

// ========== SECURITY LOGGING ==========

fn log_security_event(event_type: &str, details: &str, req: &HttpRequest) {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let conn_info = req.connection_info();
    let ip = conn_info.peer_addr().unwrap_or("unknown");
    
    // Anonymize IP using SHA256
    let mut hasher = Sha256::new();
    hasher.update(ip.as_bytes());
    let ip_hash = BASE64.encode(hasher.finalize());

    let user_agent = req.headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    
    warn!("SECURITY EVENT: {}", event_type);
    info!("   Time: {}", timestamp);
    info!("   IP (Hashed): {}", ip_hash); // Hashed IP
    info!("   User-Agent: {}", user_agent);
    info!("   Details: {}", details);
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

    // Create failed_logins table for lockout
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS failed_logins (
            username TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL DEFAULT 0,
            locked_until DATETIME
        )
        "#,
    )
    .execute(&pool)
    .await?;

    // Create refresh_tokens table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        "#,
    )
    .execute(&pool)
    .await?;

    // Create token_blacklist table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS token_blacklist (
            jti TEXT PRIMARY KEY,
            expires_at DATETIME NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await?;

    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await?;

    if user_count.0 == 0 {
        let admin_password = hash("Admin123!@#Secure", DEFAULT_COST).unwrap();
        let user_password = hash("User123!@#Secure", DEFAULT_COST).unwrap();

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
            .bind(encrypt_string("Belajar Rust Security"))
            .bind(false)
            .bind(1)
            .execute(&pool)
            .await?;

        sqlx::query("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)")
            .bind(encrypt_string("Setup authentication & database"))
            .bind(true)
            .bind(1)
            .execute(&pool)
            .await?;

        info!("✅ Default users created successfully!");
    }

    Ok(pool)
}

// ========== HELPER FUNCTIONS ==========

fn create_jwt(user_id: i64) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expiration = now
        .checked_add_signed(Duration::minutes(15)) // 15 Minutes
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id,
        exp: expiration,
        iat: now.timestamp() as usize,
        aud: "todo-app".to_string(),
        iss: "todo-auth-server".to_string(),
        jti: format!("id-{}", now.timestamp_nanos_opt().unwrap_or(0)),
    };

    let secret = get_jwt_secret().map_err(|_| jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat))?;
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&secret),
    )
}

fn generate_refresh_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let token: String = (0..32).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect();
    token
}


fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = get_jwt_secret().map_err(|_| jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidKeyFormat))?;
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.leeway = 0;
    validation.set_audience(&["todo-app"]);
    validation.set_issuer(&["todo-auth-server"]);

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&secret),
        &validation,
    )?;
    Ok(token_data.claims)
}

// 🔒 CRITICAL SECURITY: Enhanced token validation with database verification
async fn get_user_from_token(req: &HttpRequest, pool: &SqlitePool) -> Result<User, String> {
    // 1. Get token from HttpOnly cookie
    let token_cookie = req.cookie("auth_token")
        .ok_or("Missing auth token")?;
    let token = token_cookie.value();

    // 2. CSRF Protection (Double Submit Cookie Pattern)
    // Only check for state-changing methods
    let method = req.method();
    if *method == Method::POST || *method == Method::PUT || *method == Method::DELETE {
        let csrf_cookie = req.cookie("XSRF-TOKEN")
            .ok_or("Missing CSRF cookie")?;
        
        let csrf_header = req.headers()
            .get("X-XSRF-TOKEN")
            .ok_or("Missing X-XSRF-TOKEN header")?
            .to_str()
            .map_err(|_| "Invalid CSRF header")?;

        if csrf_cookie.value() != csrf_header {
            log_security_event(
                "CSRF_ATTACK",
                "CSRF token mismatch detected",
                req
            );
            return Err("CSRF token validation failed".to_string());
        }
    }

    // Verify JWT signature and expiration
    let claims = verify_jwt(token).map_err(|e| {
        log_security_event(
            "INVALID_TOKEN",
            &format!("JWT verification failed: {:?}", e),
            req
        );
        "Invalid or expired token".to_string()
    })?;

    // 2. CHECK BLACKLIST
    let blacklisted: Option<(String,)> = sqlx::query_as("SELECT jti FROM token_blacklist WHERE jti = ?")
        .bind(&claims.jti)
        .fetch_optional(pool)
        .await
        .map_err(|_| "Database error".to_string())?; // Added .to_string() for type consistency

    if blacklisted.is_some() {
        log_security_event(
            "BLACKLISTED_TOKEN_USED",
            &format!("Attempt to use blacklisted token: {}", claims.jti),
            req
        );
        return Err("Token is blacklisted".to_string());
    }

    // 🔒 SECURITY: Verify user exists in database
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
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
        })?
        .ok_or_else(|| { // Changed to ok_or_else to avoid creating string if not needed
            log_security_event(
                "TOKEN_WITH_INVALID_USER",
                &format!("Token claims user_id {} but user not found in database", claims.sub),
                req
            );
            "User not found - token may be forged".to_string()
        })?;

    Ok(user)
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

    if let Err(e) = validate_password(&req_body.password) {
        return HttpResponse::BadRequest().json(serde_json::json!({
             "error": e
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

            let refresh_token_val = generate_refresh_token();
            let refresh_exp = Utc::now().naive_utc() + chrono::Duration::days(7); // Refresh token valid for 7 days

            let _ = sqlx::query("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)")
                .bind(user_id)
                .bind(&refresh_token_val)
                .bind(refresh_exp)
                .execute(&data.db)
                .await;

            // Create HttpOnly Cookie for Auth
            let auth_cookie = Cookie::build("auth_token", token)
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::None)
                .max_age(CookieDuration::minutes(15)) // JWT valid for 15 minutes
                .finish();

            // Create HttpOnly Cookie for Refresh Token
            let refresh_cookie = Cookie::build("refresh_token", refresh_token_val)
                .path("/api/refresh") // Restricted path for refresh token
                .secure(true)
                .http_only(true)
                .same_site(SameSite::None)
                .max_age(CookieDuration::days(7)) // Refresh token valid for 7 days
                .finish();

            // Create Readable Cookie for CSRF (Double Submit)
            // Using a simple random-ish string here for demonstration
            let csrf_token = format!("csrf-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));

            let csrf_cookie = Cookie::build("XSRF-TOKEN", csrf_token)
                .path("/")
                .secure(true)
                .http_only(false) // JavaScript readable
                .same_site(SameSite::None)
                .max_age(CookieDuration::hours(24))
                .finish();

            HttpResponse::Ok()
                .cookie(auth_cookie)
                .cookie(refresh_cookie)
                .cookie(csrf_cookie)
                .json(LoginResponse {
                    // token removed from body
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
    login_data: web::Json<LoginRequest>,
) -> impl Responder {
    // 1. CHECK LOCKOUT STATUS
    #[derive(FromRow)]
    struct LockoutInfo {
        locked_until: Option<chrono::NaiveDateTime>,
    }

    let lockout: Option<LockoutInfo> = sqlx::query_as("SELECT locked_until FROM failed_logins WHERE username = ?")
        .bind(&login_data.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if let Some(info) = lockout {
        if let Some(locked_until) = info.locked_until {
             if Utc::now().naive_utc() < locked_until {
                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Account is locked due to too many failed attempts. Try again later."
                }));
             }
        }
    }

    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE username = ?")
        .bind(&login_data.username)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    let user = match user {
        Some(u) => u,
        None => {
             // Fake verification to prevent timing attacks logic could go here, 
             // but for now we prioritize handling the failed attempt counter even for non-existent users? 
             // Ideally we shouldn't track non-existent users to avoid DB bloat, 
             // or we DO track them to detect spray attacks. 
             // For this specific logic, if user not found, we just return error (or generic error).
             // But simpler: just return Unauthorized.
             log_security_event(
                "LOGIN_FAILED",
                &format!("Login attempt with non-existent username: {}", login_data.username),
                &req
            );
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            }));
        }
    };

    let verify_result = verify(&login_data.password, &user.password).unwrap_or(false);

    if verify_result {
        // RESET FAILED ATTEMPTS
        let _ = sqlx::query("DELETE FROM failed_logins WHERE username = ?")
            .bind(&login_data.username)
            .execute(&data.db)
            .await;

        let token = match create_jwt(user.id) {
            Ok(t) => t,
            Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Gagal membuat token"
            })),
        };

        // Generate and store refresh token
        let refresh_token_val = generate_refresh_token();
        let refresh_exp = Utc::now().naive_utc() + chrono::Duration::days(7); // Refresh token valid for 7 days

        // Invalidate any existing refresh tokens for this user (optional, but good for security)
        let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
            .bind(user.id)
            .execute(&data.db)
            .await;

        let _ = sqlx::query("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)")
            .bind(user.id)
            .bind(&refresh_token_val)
            .bind(refresh_exp)
            .execute(&data.db)
            .await;

    // Create HttpOnly Cookie for Auth
    let auth_cookie = Cookie::build("auth_token", token)
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(CookieDuration::minutes(15)) // JWT valid for 15 minutes
        .finish();

    // Create HttpOnly Cookie for Refresh Token
    let refresh_cookie = Cookie::build("refresh_token", refresh_token_val)
        .path("/api/refresh") // Restricted path for refresh token
        .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(CookieDuration::days(7)) // Refresh token valid for 7 days
        .finish();

    // Create Readable Cookie for CSRF
    let csrf_token = format!("csrf-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));

    let csrf_cookie = Cookie::build("XSRF-TOKEN", csrf_token)
        .path("/")
        .secure(true)
        .http_only(false)
        .same_site(SameSite::None)
        .max_age(CookieDuration::hours(24))
        .finish();

    log_security_event(
        "LOGIN_SUCCESS",
        &format!("User logged in: {} (ID: {})", user.username, user.id),
        &req
    );

    HttpResponse::Ok()
        .cookie(auth_cookie)
        .cookie(refresh_cookie)
        .cookie(csrf_cookie)
        .json(LoginResponse {
            user: UserInfo {
                id: user.id,
                username: user.username,
                role: UserRole::from_string(&user.role),
            },
        })

    } else {
        // INCREMENT FAILED ATTEMPTS
        // Upsert logic for SQLite
        let _ = sqlx::query(
            r#"
            INSERT INTO failed_logins (username, attempts, locked_until)
            VALUES (?, 1, NULL)
            ON CONFLICT(username) DO UPDATE SET
            attempts = attempts + 1
            "#
        )
        .bind(&login_data.username)
        .execute(&data.db)
        .await;

        // CHECK IF SHOULD LOCK
        let updated_attempts: i32 = sqlx::query_scalar("SELECT attempts FROM failed_logins WHERE username = ?")
             .bind(&login_data.username)
             .fetch_one(&data.db)
             .await
             .unwrap_or(0);

        if updated_attempts >= 5 {
             let lock_time = Utc::now().naive_utc() + chrono::Duration::minutes(15);
             let _ = sqlx::query("UPDATE failed_logins SET locked_until = ? WHERE username = ?")
                .bind(lock_time)
                .bind(&login_data.username)
                .execute(&data.db)
                .await;
        }

        log_security_event(
            "LOGIN_FAILED",
            &format!("Failed login attempt for user: {}", login_data.username),
            &req
        );
        
        HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid credentials"
        }))
    }
}

// ========== REFRESH TOKEN HANDLER ==========

#[derive(Serialize)]
struct RefreshResponse {
    message: String,
}

async fn refresh_token(
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // 1. Get refresh token from cookie
    let refresh_cookie = match req.cookie("refresh_token") {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing refresh token"})),
    };
    let refresh_token_str = refresh_cookie.value();

    // 2. Find token in DB
    #[derive(FromRow)]
    struct RefreshTokenRow {
        id: i64,
        user_id: i64,
        expires_at: chrono::NaiveDateTime,
        used: bool,
    }

    let token_row: Option<RefreshTokenRow> = sqlx::query_as("SELECT id, user_id, expires_at, used FROM refresh_tokens WHERE token_hash = ?")
        .bind(refresh_token_str)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    match token_row {
        Some(row) => {
            // 3. Security Checks
            // A. Check if used (Reuse Detection)
            if row.used {
                // 🚨 CRITICAL: Token reused! This implies theft!
                // Action: Revoke ALL tokens for this user immediately
                let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
                    .bind(row.user_id)
                    .execute(&data.db)
                    .await;
                
                log_security_event(
                    "REFRESH_TOKEN_REUSE",
                    &format!("Detailed reused detected for user {}. All sessions revoked.", row.user_id),
                    &req
                );

                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Invalid token (reuse detected)"
                }));
            }

            // B. Check expiration
            if Utc::now().naive_utc() > row.expires_at {
                 return HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Refresh token expired"
                }));
            }

            // 4. Token valid! Rotate it.
            // A. Mark current as used
            let _ = sqlx::query("UPDATE refresh_tokens SET used = 1 WHERE id = ?")
                .bind(row.id)
                .execute(&data.db)
                .await;

            // B. Generate NEW access token
            let new_access_token = match create_jwt(row.user_id) {
                Ok(t) => t,
                Err(_) => return HttpResponse::InternalServerError().finish(),
            };

            // C. Generate NEW refresh token
            let new_refresh_token = generate_refresh_token();
            let new_exp = Utc::now().naive_utc() + chrono::Duration::days(7);

            let _ = sqlx::query("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)")
                .bind(row.user_id)
                .bind(&new_refresh_token)
                .bind(new_exp)
                .execute(&data.db)
                .await;

            // 5. Send new cookies
            let auth_cookie = Cookie::build("auth_token", new_access_token)
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::None)
                .max_age(CookieDuration::minutes(15))
                .finish();

            let refresh_cookie = Cookie::build("refresh_token", new_refresh_token)
                .path("/api/refresh")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::None)
                .max_age(CookieDuration::days(7))
                .finish();

            log_security_event(
                "TOKEN_REFRESHED",
                &format!("User {} refreshed tokens", row.user_id),
                &req
            );

            HttpResponse::Ok()
                .cookie(auth_cookie)
                .cookie(refresh_cookie)
                .json(RefreshResponse { message: "Tokens refreshed".to_string() })
        },
        None => {
            HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid refresh token"
            }))
        }
    }
}

async fn get_current_user(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> impl Responder {
    match get_user_from_token(&req, &data.db).await {
        Ok(user) => HttpResponse::Ok().json(UserInfo {
            id: user.id,
            username: user.username,
            role: UserRole::from_string(&user.role),
        }),
        Err(e) => HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    }
}

async fn logout(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    // 1. Blacklist Access Token
    if let Some(cookie) = req.cookie("auth_token") {
        let token_str = cookie.value();
        if let Ok(claims) = verify_jwt(token_str) {
             let _ = sqlx::query("INSERT INTO token_blacklist (jti, expires_at) VALUES (?, ?)")
                .bind(claims.jti)
                .bind(chrono::DateTime::from_timestamp(claims.exp as i64, 0).unwrap_or_default().naive_utc())
                .execute(&data.db)
                .await;
        }
    }

    // 2. Revoke Refresh Token
    if let Some(cookie) = req.cookie("refresh_token") {
         let _ = sqlx::query("DELETE FROM refresh_tokens WHERE token_hash = ?")
            .bind(cookie.value())
            .execute(&data.db)
            .await;
    }

    // 3. Clear Cookies
    let auth_cookie = Cookie::build("auth_token", "")
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(CookieDuration::new(0, 0))
        .finish();

    let refresh_cookie = Cookie::build("refresh_token", "")
        .path("/api/refresh")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(CookieDuration::new(0, 0))
        .finish();

    let csrf_cookie = Cookie::build("XSRF-TOKEN", "")
        .path("/")
        .secure(true)
        .http_only(false)
        .same_site(SameSite::None)
        .max_age(CookieDuration::new(0, 0))
        .finish();

    HttpResponse::Ok()
        .cookie(auth_cookie)
        .cookie(refresh_cookie)
        .cookie(csrf_cookie)
        .json(serde_json::json!({ "message": "Logged out" }))
}

// ========== TODO HANDLERS ==========

async fn get_todos(
    req: HttpRequest,
    data: web::Data<AppState>,
    query: web::Query<PaginationParams>
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    let limit = query.limit.unwrap_or(20).min(100); // Default 20, max 100
    let offset = (query.page.unwrap_or(1) - 1) * limit; // Page 1-based

    // Add Audit Log for mass access approach
    if limit > 50 {
         log_security_event(
            "MASS_DATA_ACCESS",
            &format!("User {} requested large dataset (limit: {})", user.username, limit),
            &req
        );
    }

    let todos = sqlx::query_as::<_, Todo>("SELECT * FROM todos WHERE user_id = ? LIMIT ? OFFSET ?")
        .bind(user.id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&data.db)
        .await
        .unwrap_or(vec![]);
    
    // Decrypt titles
    let decrypted_todos: Vec<Todo> = todos.into_iter().map(|mut t| {
        if let Some(decrypted) = decrypt_string(&t.title) {
            t.title = decrypted;
        } else {
             t.title = "[Encrypted/Corrupt Data]".to_string();
        }
        t
    }).collect();

    HttpResponse::Ok().json(decrypted_todos)
}

async fn create_todo(
    req: HttpRequest,
    data: web::Data<AppState>,
    todo_data: web::Json<CreateTodo>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    if todo_data.title.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Title cannot be empty" }));
    }

    // Encrypt title before insert
    let encrypted_title = encrypt_string(&todo_data.title);

    let result = sqlx::query("INSERT INTO todos (title, completed, user_id) VALUES (?, ?, ?)")
        .bind(encrypted_title)
        .bind(false)
        .bind(user.id)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => HttpResponse::Ok().json(Todo {
            id: res.last_insert_rowid(),
            title: todo_data.title.clone(),
            completed: false,
            user_id: user.id,
        }),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to create todo" })),
    }
}

async fn update_todo(
    req: HttpRequest,
    data: web::Data<AppState>,
    path: web::Path<i64>,
    todo_data: web::Json<UpdateTodo>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    let todo_id = path.into_inner();

    // Verify ownership
    let todo: Option<Todo> = sqlx::query_as("SELECT * FROM todos WHERE id = ? AND user_id = ?")
        .bind(todo_id)
        .bind(user.id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

    if todo.is_none() {
        return HttpResponse::NotFound().json(serde_json::json!({ "error": "Todo not found" }));
    }

    if let Some(title) = &todo_data.title {
        if title.trim().is_empty() {
             return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Title cannot be empty" }));
        }
    }

    let mut tx = match data.db.begin().await {
        Ok(tx) => tx,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if let Some(title) = &todo_data.title {
        let encrypted_title = encrypt_string(title);
        let _ = sqlx::query("UPDATE todos SET title = ? WHERE id = ?")
            .bind(encrypted_title)
            .bind(todo_id)
            .execute(&mut *tx)
            .await;
    }

    if let Some(completed) = todo_data.completed {
        let _ = sqlx::query("UPDATE todos SET completed = ? WHERE id = ?")
            .bind(completed)
            .bind(todo_id)
            .execute(&mut *tx)
            .await;
    }

    if let Err(_) = tx.commit().await {
        return HttpResponse::InternalServerError().finish();
    }

    // Fetch updated todo to return
    let updated_todo: Todo = sqlx::query_as("SELECT * FROM todos WHERE id = ?")
        .bind(todo_id)
        .fetch_one(&data.db)
        .await
        .unwrap();

    // Decrypt title for response
    let final_todo = if let Some(decrypted) = decrypt_string(&updated_todo.title) {
        Todo { title: decrypted, ..updated_todo }
    } else {
        updated_todo
    };

    HttpResponse::Ok().json(final_todo)
}

async fn toggle_todo(
    req: HttpRequest,
    data: web::Data<AppState>,
    path: web::Path<i64>,
) -> impl Responder {
    // Re-use update logic (simplified) or separate endpoint
    // We already have generic update, but user asked for toggle specifically often
    // Let's implement it separately reusing update logic effectively
    let user = match get_user_from_token(&req, &data.db).await {
         Ok(u) => u,
         Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };
    let todo_id = path.into_inner();

    let todo: Option<Todo> = sqlx::query_as("SELECT * FROM todos WHERE id = ? AND user_id = ?")
        .bind(todo_id)
        .bind(user.id)
        .fetch_optional(&data.db)
        .await
        .unwrap_or(None);

     if let Some(t) = todo {
        let new_status = !t.completed;
        let _ = sqlx::query("UPDATE todos SET completed = ? WHERE id = ?")
            .bind(new_status)
            .bind(todo_id)
            .execute(&data.db)
            .await;
        
        HttpResponse::Ok().json(serde_json::json!({ "id": todo_id, "completed": new_status }))
     } else {
        HttpResponse::NotFound().json(serde_json::json!({ "error": "Todo not found" }))
     }
}

async fn delete_todo(
    req: HttpRequest,
    data: web::Data<AppState>,
    path: web::Path<i64>,
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    let todo_id = path.into_inner();

    let result = sqlx::query("DELETE FROM todos WHERE id = ? AND user_id = ?")
        .bind(todo_id)
        .bind(user.id)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                HttpResponse::Ok().json(serde_json::json!({ "message": "Todo deleted" }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({ "error": "Todo not found" }))
            }
        },
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to delete todo" })),
    }
}

// ========== ADMIN HANDLERS ==========

async fn get_all_users(
    req: HttpRequest,
    data: web::Data<AppState>
) -> impl Responder {
    let user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    if user.role != "Admin" {
        log_security_event(
            "UNAUTHORIZED_ADMIN_ACCESS",
            &format!("User {} attempted to access admin area", user.username),
            &req
        );
        return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Admin access required" }));
    }

    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
        .fetch_all(&data.db)
        .await
        .unwrap_or(vec![]);

    let safe_users: Vec<UserInfo> = users.into_iter().map(|u| UserInfo {
        id: u.id,
        username: u.username,
        role: UserRole::from_string(&u.role),
    }).collect();

    HttpResponse::Ok().json(safe_users)
}

async fn create_user(
    req: HttpRequest,
    data: web::Data<AppState>,
    user_data: web::Json<CreateUserRequest>,
) -> impl Responder {
    let admin_user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    if admin_user.role != "Admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Admin access required" }));
    }

     // Validate new user password policy
     if let Err(e) = validate_password(&user_data.password) {
        return HttpResponse::BadRequest().json(serde_json::json!({
             "error": e
        }));
    }

    let hashed_password = hash(&user_data.password, DEFAULT_COST).unwrap();
    let role_str = user_data.role.to_string();

    let result = sqlx::query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
        .bind(&user_data.username)
        .bind(hashed_password)
        .bind(role_str)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
             log_security_event(
                "ADMIN_CREATED_USER",
                &format!("Admin {} created new user {}", admin_user.username, user_data.username),
                &req
            );
            HttpResponse::Ok().json(serde_json::json!({ "message": "User created" }))
        },
        Err(_) => HttpResponse::BadRequest().json(serde_json::json!({ "error": "Username probably exists" })),
    }
}

async fn update_user(
    req: HttpRequest,
    data: web::Data<AppState>,
    path: web::Path<i64>,
    user_data: web::Json<UpdateUserRequest>,
) -> impl Responder {
    let admin_user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    if admin_user.role != "Admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Admin access required" }));
    }

    let target_user_id = path.into_inner();

    // Prevent Self-Demotion (Mass Assignment Fix)
    if target_user_id == admin_user.id {
        if let Some(new_role) = &user_data.role {
            if *new_role != UserRole::Admin {
                 return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "You cannot demote your own admin account"
                }));
            }
        }
    }

    let mut query_builder = sqlx::QueryBuilder::new("UPDATE users SET ");
    let mut separated = query_builder.separated(", ");

    if let Some(username) = &user_data.username {
        separated.push("username = ");
        separated.push_bind_unseparated(username);
    }

    if let Some(password) = &user_data.password {
         // Validate new password if being updated
         if let Err(e) = validate_password(password) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                 "error": e
            }));
        }
        let hashed = hash(password, DEFAULT_COST).unwrap();
        separated.push("password = ");
        separated.push_bind_unseparated(hashed);
        
        // If password changed, revoke sessions
         let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?")
            .bind(target_user_id)
            .execute(&data.db)
            .await;
    }

    if let Some(role) = &user_data.role {
        separated.push("role = ");
        separated.push_bind_unseparated(role.to_string());
    }

    query_builder.push(" WHERE id = ");
    query_builder.push_bind(target_user_id);

    let query = query_builder.build();
    let result = query.execute(&data.db).await;

    match result {
        Ok(_) => {
             log_security_event(
                "ADMIN_UPDATED_USER",
                &format!("Admin {} updated user ID {}", admin_user.username, target_user_id),
                &req
            );
            HttpResponse::Ok().json(serde_json::json!({ "message": "User updated" }))
        },
        Err(e) => {
             error!("Error updating user: {:?}", e); // Fixed structured logging
             HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Update failed" }))
        },
    }
}

async fn delete_user(
    req: HttpRequest,
    data: web::Data<AppState>,
    path: web::Path<i64>,
) -> impl Responder {
    let admin_user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    if admin_user.role != "Admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Admin access required" }));
    }
    
    let target_id = path.into_inner();
    
    // Self-deletion check
    if target_id == admin_user.id {
         return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Cannot delete self" }));
    }

    let result = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(target_id)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
            log_security_event(
                "ADMIN_DELETED_USER",
                &format!("Admin {} deleted user ID {}", admin_user.username, target_id),
                &req
            );
            HttpResponse::Ok().json(serde_json::json!({ "message": "User deleted" }))
        },
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "Failed to delete user" })),
    }
}

// ========== ADMIN HELPERS ==========

async fn get_user_todos_admin(
    req: HttpRequest,
    data: web::Data<AppState>,
    path: web::Path<i64>,
) -> impl Responder {
    let admin_user = match get_user_from_token(&req, &data.db).await {
        Ok(u) => u,
        Err(e) => return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e })),
    };

    if admin_user.role != "Admin" {
        return HttpResponse::Forbidden().json(serde_json::json!({ "error": "Admin access required" }));
    }

    let target_user_id = path.into_inner();

    let todos = sqlx::query_as::<_, Todo>("SELECT * FROM todos WHERE user_id = ?")
        .bind(target_user_id)
        .fetch_all(&data.db)
        .await
        .unwrap_or(vec![]);
    
    // Decrypt titles
    let decrypted_todos: Vec<Todo> = todos.into_iter().map(|mut t| {
        if let Some(decrypted) = decrypt_string(&t.title) {
            t.title = decrypted;
        } else {
             t.title = "[Encrypted/Corrupt Data]".to_string();
        }
        t
    }).collect();

    log_security_event(
        "ADMIN_VIEWED_USER_TODOS",
        &format!("Admin {} viewed todos for user ID {}", admin_user.username, target_user_id),
        &req
    );

    HttpResponse::Ok().json(decrypted_todos)
}

// ========== MAIN ==========


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok(); // Load .env file
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    info!("\n🔐 ULTRA SECURE TODO APP - INITIALIZING");
    info!("==========================================");
    
    info!("\n🔧 Initializing database...");
    let pool = init_database().await.expect("Failed to initialize database");
    info!("✅ Database initialized!");

    info!("\n🚀 Server Configuration:");
    info!("   Address: http://localhost:8080");
    info!("   Database: todo_app.db");
    
    info!("\n🔑 Demo Accounts:");
    info!("   Admin: admin / Admin123!@#Secure");
    info!("   User:  user  / User123!@#Secure");
    
    info!("\n🛡️  SECURITY FEATURES ENABLED:");
    info!("   ✅ JWT with strong secret key");
    info!("   ✅ Database user verification on every request");
    info!("   ✅ Token forgery detection");
    info!("   ✅ Comprehensive security logging");
    info!("   ✅ Role-based access control");
    info!("   ✅ Input validation");
    info!("   ✅ CORS protection");
    info!("   ✅ Foreign key constraints");
    info!("   ✅ Timestamp tracking");
    
    warn!("\n⚠️  SECURITY NOTES:");
    warn!("   • Set JWT_SECRET environment variable in production");
    warn!("   • Monitor security_logs table for suspicious activity");
    warn!("   • Change default passwords immediately");
    warn!("   • Use HTTPS in production");
    
    info!("\n==========================================");
    info!("Server is ready to accept connections\n");

    let app_state = web::Data::new(AppState { db: pool });

    HttpServer::new(move || {
        // Rate Limiting Configuration
        // Allow 5 requests per second (burst)
        let governor_conf = GovernorConfigBuilder::default()
            .seconds_per_request(1)
            .burst_size(5)
            .finish()
            .unwrap();

        let cors = Cors::default()
            .allowed_origin("https://porsha-brainlike-bula.ngrok-free.dev")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
            ])
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .wrap(
                actix_web::middleware::DefaultHeaders::new()
                    .add(("X-Frame-Options", "DENY"))
                    .add(("X-Content-Type-Options", "nosniff"))
                    .add(("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"))
                    .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
                    .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
                    .add(("Permissions-Policy", "camera=(), microphone=(), geolocation=()"))
            )
            .wrap(Governor::new(&governor_conf))
            .app_data(app_state.clone())
            .app_data(web::JsonConfig::default().limit(1024 * 1024)) // 1MB limit
            .route("/api/register", web::post().to(register))
            .route("/api/login", web::post().to(login))
            .route("/api/me", web::get().to(get_current_user))
            .route("/api/logout", web::post().to(logout))
            .route("/api/refresh", web::post().to(refresh_token)) // Refresh Route
            .route("/api/todos", web::get().to(get_todos))
            .route("/api/todos", web::post().to(create_todo))
            .route("/api/todos/{id}", web::put().to(update_todo))
            .route("/api/todos/{id}/toggle", web::put().to(toggle_todo))
            .route("/api/todos/{id}", web::delete().to(delete_todo))
            .route("/api/admin/users", web::get().to(get_all_users))
            .route("/api/admin/users", web::post().to(create_user))
            .route("/api/admin/users/{id}", web::put().to(update_user))
            .route("/api/admin/users/{id}", web::delete().to(delete_user))
            .route("/api/admin/users/{id}/todos", web::get().to(get_user_todos_admin))
            .route("/api/logout", web::post().to(logout))
            .route("/", web::get().to(index))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
