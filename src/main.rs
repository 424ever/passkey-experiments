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
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

static SESSION_COOKIE: &'static str = "SESSION";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
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
        });

    let listener = TcpListener::bind("0.0.0.0:4242").await.unwrap();
    serve(listener, app).await.unwrap()
}

async fn get_session(parts: &mut Parts, store: &MemoryStore) -> Option<Session> {
    let cookies = parts.extract::<TypedHeader<headers::Cookie>>().await.ok()?;
    let session = cookies.get(SESSION_COOKIE)?;
    store.load_session(session.into()).await.unwrap()
}

#[derive(Clone)]
struct AppState {
    store: MemoryStore,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

#[derive(Serialize, Deserialize)]
struct UserId(u64);

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

async fn root() -> impl IntoResponse {
    Html(include_str!("../pages/root.html"))
}

async fn status(user: Option<UserId>) -> impl IntoResponse {
    match user {
        Some(user) => Html(format!("you are user {}", user.0)),
        None => Html("you are not logged in".into()),
    }
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
    State(store): State<MemoryStore>,
    Form(login): Form<Login>,
) -> Result<impl IntoResponse, Redirect> {
    if login.user != "jonas" || login.pass != "password" {
        return Err(Redirect::to("/loginfail"));
    }
    let mut session = Session::new();
    session.insert("user", UserId(1)).unwrap();
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
