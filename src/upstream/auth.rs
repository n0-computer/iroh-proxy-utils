use std::future::Future;

use dynosaur::dynosaur;
use iroh::EndpointId;
use n0_error::StackError;

use crate::parse::HttpProxyRequest;

/// Authorization failure reasons.
///
/// Returned by [`AuthHandler::authorize`] to indicate why a request was rejected.
/// The upstream proxy responds with 403 Forbidden for all variants.
#[derive(StackError)]
pub enum AuthError {
    /// Credentials are malformed or failed validation.
    InvalidCredentials,
    /// Credentials were valid but have expired.
    TokenExpired,
    /// Authorization denied for this request.
    Forbidden,
    /// Request is invalid for the authentication scheme.
    BadRequest,
}

#[dynosaur(pub(crate) DynAuthHandler = dyn(box) AuthHandler)]
/// Authorizes proxy requests from remote endpoints.
///
/// Implement this trait to control which requests are allowed through the
/// upstream proxy. Authorization decisions can be based on the remote endpoint
/// identity, request target, headers, or any other criteria.
pub trait AuthHandler: Send + Sync {
    /// Checks if the request from `remote_id` should be authorized.
    ///
    /// Returns `Ok(())` to allow the request, or an [`AuthError`] to reject it.
    fn authorize<'a>(
        &'a self,
        remote_id: EndpointId,
        req: &'a HttpProxyRequest,
    ) -> impl Future<Output = Result<(), AuthError>> + Send + 'a;
}

/// Authorization handler that rejects all requests with 403 Forbidden.
#[derive(Debug, Default)]
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

/// Authorization handler that accepts all requests unconditionally.
///
/// Suitable for testing or when authorization is handled elsewhere.
#[derive(Debug, Default)]
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
