//! This file is part of the `secret_provider` module, which defines a trait for providing secrets

use std::net::SocketAddr;

/// Trait for providing secrets based on client address
pub trait SecretProvider: Send + Sync + 'static {
    /// Retrieves a secret for the given client address.
    fn get_secret(&self, client_addr: &SocketAddr) -> Option<Vec<u8>>;
}

/// Default implementation of the SecretProvider trait
pub struct DefaultSecretProvider;
impl SecretProvider for DefaultSecretProvider {
    fn get_secret(&self, _client_addr: &SocketAddr) -> Option<Vec<u8>> {
        // Default implementation returns None, meaning no secret is provided
        None
    }
}

impl Default for DefaultSecretProvider {
    fn default() -> Self {
        DefaultSecretProvider
    }
}
