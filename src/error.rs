use std::fmt::Display;

use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};

#[derive(Debug)]
pub enum AuthRejection {
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

#[derive(Debug)]
pub struct AppError(anyhow::Error);

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

#[derive(Debug)]
pub struct ApiError(String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = Response::new(Body::new(self.0));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        resp
    }
}

impl<T> From<T> for ApiError
where
    T: Display,
{
    fn from(value: T) -> Self {
        Self(value.to_string())
    }
}
