use std::num::NonZeroU32;

use anyhow::Context;
use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};
use axum_extra::{TypedHeader, headers};
use rusqlite::{
    Connection, OptionalExtension,
    types::{FromSql, FromSqlResult, ValueRef},
};

use crate::{SESSION_COOKIE, Sessions, error::AuthRejection};

#[derive(Clone, Copy, Debug)]
pub struct UserId(NonZeroU32);

#[derive(Debug)]
pub struct User {
    pub id: UserId,
    pub name: String,
    // TODO: security
    pub pass: String,
}

pub fn load_user_by_name(db: &Connection, name: &str) -> anyhow::Result<Option<User>> {
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

pub fn load_user_by_id(db: &Connection, id: UserId) -> anyhow::Result<Option<User>> {
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

impl FromSql for UserId {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        <NonZeroU32 as FromSql>::column_result(value).map(Self)
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
