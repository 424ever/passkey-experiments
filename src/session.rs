use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};
use axum_extra::{
    TypedHeader,
    headers::{self},
};

use crate::{SESSION_COOKIE, Sessions, error::AuthRejection, pk::Challenge, user::UserId};

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub user: UserId,
    pub create_pk_challenge: Option<Challenge>,
}

impl<S> FromRequestParts<S> for Session
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
        let session = *store
            .read()
            .await
            .get(session)
            .ok_or(AuthRejection::Redirect)?;

        Ok(session)
    }
}

impl<S> OptionalFromRequestParts<S> for Session
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
            <Self as FromRequestParts<S>>::from_request_parts(parts, state).await.ok(),
        )
    }
}
