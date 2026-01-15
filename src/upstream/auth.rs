use std::future::Future;

use dynosaur::dynosaur;
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

#[dynosaur(pub(crate) DynAuthHandler = dyn(box) AuthHandler)]
pub trait AuthHandler: Send + Sync {
    fn authorize<'a>(
        &'a self,
        remote_id: EndpointId,
        req: &'a HttpRequest,
    ) -> impl Future<Output = Result<(), AuthError>> + Send + 'a;
}

#[derive(Debug)]
pub struct DenyAll;

impl AuthHandler for DenyAll {
    fn authorize<'a>(
        &'a self,
        _remote_id: EndpointId,
        _req: &'a HttpRequest,
    ) -> impl Future<Output = Result<(), AuthError>> + Send + 'a {
        async move { Err(AuthError::Forbidden) }
    }
}

#[derive(Debug)]
pub struct AcceptAll;

impl AuthHandler for AcceptAll {
    fn authorize<'a>(
        &'a self,
        _remote_id: EndpointId,
        _req: &'a HttpRequest,
    ) -> impl Future<Output = Result<(), AuthError>> + Send + 'a {
        async move { Ok(()) }
    }
}
