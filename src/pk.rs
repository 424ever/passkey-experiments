use anyhow::Context;
use axum::{Json, Router, extract::State, routing::get};
use axum_extra::{TypedHeader, headers};
use rand::{Rng, rng};

use crate::{
    AppState, SESSION_COOKIE,
    error::AppError,
    pk::types::public_key_credential::{self},
    user::load_user_by_id,
};

mod types;

pub type Challenge = [u8; 16];

pub fn routes() -> Router<AppState> {
    Router::new().route("/get-creation-options", get(get_creation_options))
}

async fn get_creation_options(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<Json<public_key_credential::CreationOptions>, AppError> {
    use public_key_credential::*;

    let cookie = cookies.get(SESSION_COOKIE).context("not in a session")?;
    let mut session = state.sessions.write().await;
    let session = session.get_mut(cookie).context("not a valid session")?;

    let mut challenge = [0u8; 16];
    rng().fill_bytes(&mut challenge);
    session.create_pk_challenge = Some(challenge);

    let user = load_user_by_id(&*state.db.lock().await, session.user)?;

    Ok(Json(CreationOptions {
        rp: RpEntity {
            entity: Entity {
                name: "424ever.awesome-network".into(),
            },
            id: None,
        },
        user: UserEntity {
            entity: Entity {
                name: user.name.clone(),
            },
            id: Vec::from(user.id.value().to_be_bytes()),
            display_name: user.name,
        },
        challenge: challenge,
        pub_key_cred_params: vec![],
        timeout: 30000,
        exclude_credentials: None,
        authenticator_selection: None,
        attestation: None,
        extensions: None,
    }))
}
