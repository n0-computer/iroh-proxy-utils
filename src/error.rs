// TODO - these should be n0_snafu errors
#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    TokenExpired,
    Forbidden,
}

#[derive(Debug)]
pub enum TunnelError {
    MissingDestination,
    InvalidNodeId,
    Auth(AuthError),
}
