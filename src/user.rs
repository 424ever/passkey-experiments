use std::num::NonZeroU32;

use anyhow::Context;
use rusqlite::{
    Connection, OptionalExtension,
    types::{FromSql, FromSqlResult, ValueRef},
};

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

pub fn load_user_by_id(db: &Connection, id: UserId) -> anyhow::Result<User> {
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
    .context("query user by id")
}

impl UserId {
    pub fn value(&self) -> u32 {
        self.0.into()
    }
}

impl FromSql for UserId {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        <NonZeroU32 as FromSql>::column_result(value).map(Self)
    }
}
