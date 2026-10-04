use std::{num::NonZeroU32, sync::Arc};

use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    Form, RequestPartsExt, Router,
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts, State},
    http::{HeaderMap, header::SET_COOKIE, request::Parts},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    serve,
};
use axum_extra::{TypedHeader, headers};
use rusqlite::{
    Connection,
    types::{FromSql, FromSqlResult, ValueRef},
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, sync::Mutex};
use tower_http::trace::TraceLayer;

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
        .route("/status", get(status))
        .route("/logout", get(logout))
        .route("/login", get(login_page))
        .route("/login", post(login_handler))
        .route("/loginsuccess", get(loginsuccess))
        .route("/loginfail", get(loginfail))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            store: MemoryStore::new(),
            db: Arc::new(Mutex::new(connection)),
        });

    let listener = TcpListener::bind("0.0.0.0:4242").await.unwrap();
    serve(listener, app).await.unwrap()
}

async fn get_session(parts: &mut Parts, store: &MemoryStore) -> Option<Session> {
    let cookies = parts.extract::<TypedHeader<headers::Cookie>>().await.ok()?;
    let session = cookies.get(SESSION_COOKIE)?;
    store.load_session(session.into()).await.unwrap()
}

fn load_user_by_name(db: &Connection, name: &str) -> Option<User> {
    let mut stmt = db
        .prepare("SELECT id, name, pass FROM user WHERE name = ?")
        .unwrap();
    stmt.query_one((name,), |r| {
        Ok(User {
            id: r.get(0)?,
            name: r.get(1)?,
            pass: r.get(2)?,
        })
    })
    .ok()
}

fn load_user_by_id(db: &Connection, id: UserId) -> Option<User> {
    let mut stmt = db
        .prepare("SELECT id, name, pass FROM user WHERE id = ?")
        .unwrap();
    stmt.query_one((id.0,), |r| {
        Ok(User {
            id: r.get(0)?,
            name: r.get(1)?,
            pass: r.get(2)?,
        })
    })
    .ok()
}

#[derive(Clone)]
struct AppState {
    store: MemoryStore,
    db: Arc<Mutex<Connection>>,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for Arc<Mutex<Connection>> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.db)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserId(NonZeroU32);

impl<S> FromRequestParts<S> for UserId
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);
        let session = get_session(parts, &store)
            .await
            .ok_or(Redirect::to("/login"))?;
        let user = session
            .get::<UserId>("user")
            .ok_or(Redirect::to("/login"))?;

        Ok(user)
    }
}

impl<S> OptionalFromRequestParts<S> for UserId
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = !;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(
            match <Self as FromRequestParts<S>>::from_request_parts(parts, state).await {
                Ok(u) => Some(u),
                Err(_) => None,
            },
        )
    }
}

impl FromSql for UserId {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        <NonZeroU32 as FromSql>::column_result(value).map(Self)
    }
}

#[derive(Debug)]
struct User {
    id: UserId,
    name: String,
    // TODO: security
    pass: String,
}

async fn root() -> impl IntoResponse {
    Html(include_str!("../pages/root.html"))
}

async fn status(
    State(db): State<Arc<Mutex<Connection>>>,
    user: Option<UserId>,
) -> impl IntoResponse {
    let Some(user) = user else {
        return Html("you are not logged in".into());
    };
    let Some(user) = load_user_by_id(&*db.lock().await, user) else {
        return Html("reading failed".into());
    };
    Html(format!("you are {}", user.name))
}

async fn logout(
    State(store): State<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> impl IntoResponse {
    let Some(cookie) = cookies.get(SESSION_COOKIE) else {
        return Redirect::to("/");
    };
    let Some(session) = store.load_session(cookie.into()).await.unwrap() else {
        return Redirect::to("/");
    };
    store.destroy_session(session).await.unwrap();
    Redirect::to("/")
}

async fn login_page() -> impl IntoResponse {
    Html(include_str!("../pages/login.html"))
}

#[derive(Deserialize)]
struct Login {
    user: String,
    pass: String,
}

async fn login_handler(
    State(db): State<Arc<Mutex<Connection>>>,
    State(store): State<MemoryStore>,
    Form(login): Form<Login>,
) -> Result<impl IntoResponse, Redirect> {
    let Some(user) = load_user_by_name(&*db.lock().await, &login.user) else {
        return Err(Redirect::to("/loginfail"));
    };
    if user.pass != login.pass {
        return Err(Redirect::to("/loginfail"));
    }

    let mut session = Session::new();
    session.insert("user", user.id.clone()).unwrap();
    let cookie = store.store_session(session).await.unwrap().unwrap();
    let cookie = format!("{SESSION_COOKIE}={cookie}; SameSite=Lax; HttpOnly; Secure; Path=/");
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    Ok((headers, Redirect::to("/loginsuccess")))
}

async fn loginsuccess() -> impl IntoResponse {
    Html("logged in<br/><a href=\"/\">go back</a>")
}
async fn loginfail() -> impl IntoResponse {
    Html("invalid username or password<br/><a href=\"/login\">go back</a>")
}
