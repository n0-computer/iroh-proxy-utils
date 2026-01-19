use std::future::Future;

use dynosaur::dynosaur;
use iroh::EndpointId;
use n0_error::StackError;

use crate::parse::HttpProxyRequest;

/// Authorization errors for proxy requests.
#[derive(StackError)]
pub enum AuthError {
    /// Credentials are malformed or fail validation.
    InvalidCredentials,
    /// Credentials are valid but expired.
    TokenExpired,
    /// Authorization failed for this request.
    Forbidden,
    /// Request is invalid for the selected authentication scheme.
    BadRequest,
}

#[dynosaur(pub(crate) DynAuthHandler = dyn(box) AuthHandler)]
/// Authorizes a proxy request from a remote endpoint.
pub trait AuthHandler: Send + Sync {
    /// Checks authorization for the given remote endpoint and request.
    fn authorize<'a>(
        &'a self,
        remote_id: EndpointId,
        req: &'a HttpProxyRequest,
    ) -> impl Future<Output = Result<(), AuthError>> + Send + 'a;
}

/// Authorization handler that rejects all requests.
#[derive(Debug)]
pub struct DenyAll;

impl AuthHandler for DenyAll {
    async fn authorize<'a>(
        &'a self,
        _remote_id: EndpointId,
        _req: &'a HttpProxyRequest,
    ) -> Result<(), AuthError> {
        Err(AuthError::Forbidden)
    }
}

/// Authorization handler that accepts all requests.
#[derive(Debug)]
pub struct AcceptAll;

impl AuthHandler for AcceptAll {
    async fn authorize<'a>(
        &'a self,
        _remote_id: EndpointId,
        _req: &'a HttpProxyRequest,
    ) -> Result<(), AuthError> {
        Ok(())
    }
}
