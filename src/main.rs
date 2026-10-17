pub mod cbor;
mod error;
mod user;

use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

use anyhow::Context;
use axum::{
    Form, Router,
    extract::{FromRef, State},
    http::{HeaderMap, header::SET_COOKIE},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    serve,
};
use axum_extra::{TypedHeader, headers};
use rand::random;
use rusqlite::Connection;
use serde::Deserialize;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tower_http::trace::TraceLayer;

use crate::{
    error::AppError,
    user::{UserId, load_user_by_id, load_user_by_name},
};

type Sessions = Arc<RwLock<HashMap<String, UserId>>>;

static SESSION_COOKIE: &'static str = "SESSION";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let connection = Connection::open("data.db").unwrap();
    connection
        .execute(
            "CREATE TABLE IF NOT EXISTS user (
               id INTEGER PRIMARY KEY,
               name TEXT UNIQUE NOT NULL,
               pass TEXT NOT NULL
             )",
            (),
        )
        .unwrap();

    let app = Router::new()
        .route("/", get(root))
        .route("/logout", get(logout))
        .route("/login", get(login_page))
        .route("/login", post(login_handler))
        .route("/loginfail", get(loginfail))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            db: Arc::new(Mutex::new(connection)),
        });

    let listener = TcpListener::bind("0.0.0.0:4242").await.unwrap();
    serve(listener, app).await.unwrap()
}

#[derive(Clone)]
struct AppState {
    sessions: Sessions,
    db: Arc<Mutex<Connection>>,
}

impl FromRef<AppState> for Sessions {
    fn from_ref(state: &AppState) -> Self {
        state.sessions.clone()
    }
}

impl FromRef<AppState> for Arc<Mutex<Connection>> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.db)
    }
}

async fn root(
    State(db): State<Arc<Mutex<Connection>>>,
    user: Option<UserId>,
) -> Result<impl IntoResponse, AppError> {
    let mut resp = String::new();

    resp.push_str(r#"<h1>awesome website</h1>"#);
    resp.push_str(r#"<p>a place to keep your most private data</p>"#);

    if let Some(uid) = user
        && let Some(udat) = load_user_by_id(&*db.lock().await, uid)?
    {
        resp.push_str(&format!(r#"<p>hello {}</p>"#, udat.name));
        resp.push_str(r#"<p><a href="logout">logout</a></p>"#);
    } else {
        resp.push_str(r#"<p><a href="login">login</a></p>"#);
    }

    Ok(Html(resp))
}

async fn logout(
    State(store): State<Sessions>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    if let Some(cookie) = cookies.get(SESSION_COOKIE)
        && let Entry::Occupied(session) = store.write().await.entry(cookie.into())
    {
        session.remove();
    }
    Ok(Redirect::to("/"))
}

async fn login_page() -> impl IntoResponse {
    Html(
        r#"<h1>login</h1>
<form action="login" method="post">
  <div><label for="user">user</label><input id="user" name="user" type="text"/></div>
  <div><label for="pass">password</label><input id="pass" name="pass" type="password"/></div>
  <div><input type="submit"/></div>
</form>"#,
    )
}

#[derive(Debug, Deserialize)]
struct Login {
    user: String,
    pass: String,
}

async fn login_handler(
    State(db): State<Arc<Mutex<Connection>>>,
    State(store): State<Sessions>,
    Form(login): Form<Login>,
) -> Result<Response, AppError> {
    if let Some(user) = load_user_by_name(&*db.lock().await, &login.user)?
        && user.pass == login.pass
    {
        let session_key: String = random::<u64>().to_string();
        let cookie =
            format!("{SESSION_COOKIE}={session_key}; SameSite=Lax; HttpOnly; Secure; Path=/");
        let mut headers = HeaderMap::new();
        headers.insert(SET_COOKIE, cookie.parse()?);

        store
            .write()
            .await
            .insert(session_key, user.id)
            .is_none()
            .then_some(())
            .context("duplicate session key")?;

        Ok((headers, Redirect::to("/")).into_response())
    } else {
        Ok(Redirect::to("/loginfail").into_response())
    }
}

async fn loginfail() -> impl IntoResponse {
    Html("invalid username or password<br/><a href=\"/login\">go back</a>")
}
