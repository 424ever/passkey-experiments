use std::{
    collections::{HashMap, hash_map::Entry},
    num::NonZeroU32,
    sync::Arc,
};

use anyhow::Context;
use axum::{
    Form, RequestPartsExt, Router,
    body::Body,
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts, State},
    http::{HeaderMap, header::SET_COOKIE, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    serve,
};
use axum_extra::{TypedHeader, headers};
use rand::random;
use rusqlite::{
    Connection, OptionalExtension,
    types::{FromSql, FromSqlResult, ValueRef},
};
use serde::Deserialize;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tower_http::trace::TraceLayer;

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
        .route("/status", get(status))
        .route("/logout", get(logout))
        .route("/login", get(login_page))
        .route("/login", post(login_handler))
        .route("/loginsuccess", get(loginsuccess))
        .route("/loginfail", get(loginfail))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            db: Arc::new(Mutex::new(connection)),
        });

    let listener = TcpListener::bind("0.0.0.0:4242").await.unwrap();
    serve(listener, app).await.unwrap()
}

fn load_user_by_name(db: &Connection, name: &str) -> anyhow::Result<Option<User>> {
    let mut stmt = db
        .prepare("SELECT id, name, pass FROM user WHERE name = ?")
        .context("prepare user-by-name query")?;
    stmt.query_one((name,), |r| {
        Ok(User {
            id: r.get(0)?,
            name: r.get(1)?,
            pass: r.get(2)?,
        })
    })
    .optional()
    .context("query user by name")
}

fn load_user_by_id(db: &Connection, id: UserId) -> anyhow::Result<Option<User>> {
    let mut stmt = db
        .prepare("SELECT id, name, pass FROM user WHERE id = ?")
        .context("prepare user-by-id query")?;
    stmt.query_one((id.0,), |r| {
        Ok(User {
            id: r.get(0)?,
            name: r.get(1)?,
            pass: r.get(2)?,
        })
    })
    .optional()
    .context("query user by id")
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

#[derive(Clone, Copy, Debug)]
struct UserId(NonZeroU32);

#[derive(Debug)]
enum AuthRejection {
    Redirect,
    Internal(AppError),
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        match self {
            AuthRejection::Redirect => Redirect::to("/login").into_response(),
            AuthRejection::Internal(app_error) => app_error.into_response(),
        }
    }
}

impl<T> From<T> for AuthRejection
where
    T: Into<AppError>,
{
    fn from(value: T) -> Self {
        Self::Internal(value.into())
    }
}

impl<S> FromRequestParts<S> for UserId
where
    Sessions: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = Sessions::from_ref(state);
        let cookies = parts.extract::<TypedHeader<headers::Cookie>>().await?;
        let Some(session) = cookies.get(SESSION_COOKIE) else {
            return Err(AuthRejection::Redirect);
        };
        let user = store
            .read()
            .await
            .get(session)
            .ok_or(AuthRejection::Redirect)?
            .clone();

        Ok(user)
    }
}

impl<S> OptionalFromRequestParts<S> for UserId
where
    Sessions: FromRef<S>,
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
) -> Result<impl IntoResponse, AppError> {
    let Some(user) = user else {
        return Ok(Html("you are not logged in".into()));
    };
    let Some(user) = load_user_by_id(&*db.lock().await, user)? else {
        return Ok(Html("reading failed".into()));
    };
    Ok(Html(format!("you are {}", user.name)))
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
    Html(include_str!("../pages/login.html"))
}

#[derive(Debug, Deserialize)]
struct Login {
    user: String,
    pass: String,
}

#[axum::debug_handler(state = AppState)]
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

        Ok((headers, Redirect::to("/loginsuccess")).into_response())
    } else {
        Ok(Redirect::to("/loginfail").into_response())
    }
}

async fn loginsuccess() -> impl IntoResponse {
    Html("logged in<br/><a href=\"/\">go back</a>")
}
async fn loginfail() -> impl IntoResponse {
    Html("invalid username or password<br/><a href=\"/login\">go back</a>")
}

#[derive(Debug)]
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("application error: {:#}", &self.0);
        Response::new(Body::from(format!("an error occurred :(\n{:#}", self.0)))
    }
}

impl Into<Response<Body>> for AppError {
    fn into(self) -> Response<Body> {
        self.into_response()
    }
}

impl<T> From<T> for AppError
where
    T: Into<anyhow::Error>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}
