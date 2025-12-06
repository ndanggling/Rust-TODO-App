// main.rs - File utama aplikasi Rust
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_cors::Cors;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// Struct untuk merepresentasikan TODO item
// Derive Serialize dan Deserialize untuk konversi JSON
#[derive(Serialize, Deserialize, Clone)]
struct Todo {
    id: u32,
    title: String,
    completed: bool,
}

// State aplikasi yang dibungkus dengan Mutex untuk thread-safety
// Vec<Todo> adalah vector/array yang menyimpan semua TODO items
struct AppState {
    todos: Mutex<Vec<Todo>>,
}

// Handler untuk mendapatkan semua TODO items
// GET /api/todos
async fn get_todos(data: web::Data<AppState>) -> impl Responder {
    // Lock mutex untuk akses data secara aman
    let todos = data.todos.lock().unwrap();
    // Return JSON response
    HttpResponse::Ok().json(&*todos)
}

// Struct untuk menerima data TODO baru dari client
#[derive(Deserialize)]
struct CreateTodo {
    title: String,
}

// Handler untuk membuat TODO baru
// POST /api/todos
async fn create_todo(
    data: web::Data<AppState>,
    todo: web::Json<CreateTodo>,
) -> impl Responder {
    let mut todos = data.todos.lock().unwrap();
    
    // Generate ID baru (ID tertinggi + 1)
    let new_id = todos.iter().map(|t| t.id).max().unwrap_or(0) + 1;
    
    // Buat TODO baru
    let new_todo = Todo {
        id: new_id,
        title: todo.title.clone(),
        completed: false,
    };
    
    // Tambahkan ke vector
    todos.push(new_todo.clone());
    
    HttpResponse::Ok().json(new_todo)
}

// Handler untuk toggle status completed
// PUT /api/todos/{id}/toggle
async fn toggle_todo(
    data: web::Data<AppState>,
    path: web::Path<u32>,
) -> impl Responder {
    let id = path.into_inner();
    let mut todos = data.todos.lock().unwrap();
    
    // Cari TODO berdasarkan ID dan toggle statusnya
    if let Some(todo) = todos.iter_mut().find(|t| t.id == id) {
        todo.completed = !todo.completed;
        HttpResponse::Ok().json(todo.clone())
    } else {
        HttpResponse::NotFound().body("Todo not found")
    }
}

// Handler untuk menghapus TODO
// DELETE /api/todos/{id}
async fn delete_todo(
    data: web::Data<AppState>,
    path: web::Path<u32>,
) -> impl Responder {
    let id = path.into_inner();
    let mut todos = data.todos.lock().unwrap();
    
    // Cari index TODO dan hapus
    if let Some(pos) = todos.iter().position(|t| t.id == id) {
        todos.remove(pos);
        HttpResponse::Ok().body("Todo deleted")
    } else {
        HttpResponse::NotFound().body("Todo not found")
    }
}

// Handler untuk melayani file HTML frontend
async fn index() -> impl Responder {
    let html = r#"
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rust TODO App</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 50px auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 30px;
        }
        h1 {
            color: #667eea;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 0.9em;
        }
        .input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
        }
        input[type="text"] {
            flex: 1;
            padding: 15px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 16px;
            transition: border 0.3s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            padding: 15px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            transition: background 0.3s;
        }
        button:hover {
            background: #5568d3;
        }
        .todo-list {
            list-style: none;
        }
        .todo-item {
            display: flex;
            align-items: center;
            padding: 15px;
            margin-bottom: 10px;
            background: #f8f9fa;
            border-radius: 8px;
            transition: all 0.3s;
        }
        .todo-item:hover {
            background: #e9ecef;
            transform: translateX(5px);
        }
        .todo-item.completed {
            opacity: 0.6;
        }
        .todo-item.completed .todo-text {
            text-decoration: line-through;
            color: #999;
        }
        .todo-checkbox {
            width: 20px;
            height: 20px;
            margin-right: 15px;
            cursor: pointer;
        }
        .todo-text {
            flex: 1;
            font-size: 16px;
        }
        .delete-btn {
            padding: 8px 15px;
            background: #dc3545;
            font-size: 14px;
        }
        .delete-btn:hover {
            background: #c82333;
        }
        .empty-state {
            text-align: center;
            color: #999;
            padding: 40px;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🦀 Rust TODO App</h1>
        <p class="subtitle">Backend: Rust (Actix-web) | Frontend: Vanilla JS</p>
        
        <div class="input-group">
            <input type="text" id="todoInput" placeholder="Tambahkan TODO baru..." />
            <button onclick="addTodo()">Tambah</button>
        </div>
        
        <ul id="todoList" class="todo-list"></ul>
        <div id="emptyState" class="empty-state">Belum ada TODO. Mulai tambahkan sekarang!</div>
    </div>

    <script>
        const API_URL = 'http://localhost:8080/api';

        // Load semua TODO saat halaman dimuat
        async function loadTodos() {
            try {
                const response = await fetch(`${API_URL}/todos`);
                const todos = await response.json();
                renderTodos(todos);
            } catch (error) {
                console.error('Error loading todos:', error);
            }
        }

        // Render TODO items ke DOM
        function renderTodos(todos) {
            const todoList = document.getElementById('todoList');
            const emptyState = document.getElementById('emptyState');
            
            todoList.innerHTML = '';
            
            if (todos.length === 0) {
                emptyState.style.display = 'block';
                return;
            }
            
            emptyState.style.display = 'none';
            
            todos.forEach(todo => {
                const li = document.createElement('li');
                li.className = `todo-item ${todo.completed ? 'completed' : ''}`;
                li.innerHTML = `
                    <input type="checkbox" class="todo-checkbox" 
                           ${todo.completed ? 'checked' : ''} 
                           onchange="toggleTodo(${todo.id})">
                    <span class="todo-text">${todo.title}</span>
                    <button class="delete-btn" onclick="deleteTodo(${todo.id})">Hapus</button>
                `;
                todoList.appendChild(li);
            });
        }

        // Tambah TODO baru
        async function addTodo() {
            const input = document.getElementById('todoInput');
            const title = input.value.trim();
            
            if (!title) {
                alert('Masukkan TODO terlebih dahulu!');
                return;
            }
            
            try {
                await fetch(`${API_URL}/todos`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ title })
                });
                
                input.value = '';
                loadTodos();
            } catch (error) {
                console.error('Error adding todo:', error);
            }
        }

        // Toggle status completed
        async function toggleTodo(id) {
            try {
                await fetch(`${API_URL}/todos/${id}/toggle`, {
                    method: 'PUT'
                });
                loadTodos();
            } catch (error) {
                console.error('Error toggling todo:', error);
            }
        }

        // Hapus TODO
        async function deleteTodo(id) {
            try {
                await fetch(`${API_URL}/todos/${id}`, {
                    method: 'DELETE'
                });
                loadTodos();
            } catch (error) {
                console.error('Error deleting todo:', error);
            }
        }

        // Enter key untuk submit
        document.getElementById('todoInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') addTodo();
        });

        // Load todos saat halaman pertama kali dibuka
        loadTodos();
    </script>
</body>
</html>
    "#;
    
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// Fungsi main - entry point aplikasi
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Server berjalan di http://localhost:8080");
    println!("📝 Buka browser dan akses URL di atas untuk melihat aplikasi");
    
    // Inisialisasi state dengan beberapa TODO contoh
    let app_state = web::Data::new(AppState {
        todos: Mutex::new(vec![
            Todo {
                id: 1,
                title: "Belajar Rust".to_string(),
                completed: false,
            },
            Todo {
                id: 2,
                title: "Buat web app dengan Actix".to_string(),
                completed: false,
            },
        ]),
    });

    // Konfigurasi dan jalankan HTTP server
    HttpServer::new(move || {
        // Setup CORS untuk mengizinkan request dari frontend
        let cors = Cors::permissive();
        
        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            // Route untuk API endpoints
            .route("/api/todos", web::get().to(get_todos))
            .route("/api/todos", web::post().to(create_todo))
            .route("/api/todos/{id}/toggle", web::put().to(toggle_todo))
            .route("/api/todos/{id}", web::delete().to(delete_todo))
            // Route untuk frontend
            .route("/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}