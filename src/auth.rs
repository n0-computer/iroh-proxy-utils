use std::{fmt::Debug, pin::Pin};

use iroh::EndpointId;
use n0_error::StackError;

use crate::parse::HttpRequest;

#[derive(StackError)]
pub enum AuthError {
    InvalidCredentials,
    TokenExpired,
    Forbidden,
    BadRequest,
}

pub trait AuthHandler: Send + Sync + Debug {
    fn authorize<'a>(
        &'a self,
        remote_id: EndpointId,
        req: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>>;
}

#[derive(Debug)]
pub struct DenyAll;

impl AuthHandler for DenyAll {
    fn authorize<'a>(
        &'a self,
        _remote_id: EndpointId,
        _req: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        Box::pin(async move { Err(AuthError::Forbidden) })
    }
}

#[derive(Debug)]
pub struct AcceptAll;

impl AuthHandler for AcceptAll {
    fn authorize<'a>(
        &'a self,
        _remote_id: EndpointId,
        _req: &'a HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        Box::pin(async move { Ok(()) })
    }
}
