//! RADIUS Generic Server implementation

use crate::protocol::dictionary::Dictionary;
use crate::protocol::error::RadiusError;
use crate::protocol::host::Host;
use crate::protocol::radius_packet::{RadiusAttribute, RadiusMsgType, RadiusPacket, TypeCode};
use std::net::SocketAddr;

use crate::server::secret_provider::SecretProvider;
use md5::{Digest, Md5};

#[derive(Debug)]
/// Represents RADIUS Generic Server instance
pub struct Server<S: SecretProvider> {
    host: Host,
    allowed_hosts: Vec<String>,
    server: String,
    secret_provider: S,
    retries: u16,
    timeout: u16,
}

impl<S: SecretProvider> Server<S> {
    // === Builder for Server ===
    /// Initialise Server instance with dictionary (other fields would be set to default values)
    ///
    /// To be called **first** when creating RADIUS Server instance
    pub fn with_dictionary<T: SecretProvider + Default>(dictionary: Dictionary) -> Server<T> {
        let host = Host::with_dictionary(dictionary);

        Server {
            host,
            allowed_hosts: Vec::new(),
            server: String::from(""),
            secret_provider: T::default(),
            retries: 1,
            timeout: 2,
        }
    }

    /// **Required**
    ///
    /// Sets hostname to which server would bind
    pub fn set_server(mut self, server: String) -> Server<S> {
        self.server = server;
        self
    }

    ///
    ///
    /// # Arguments
    ///
    /// * `secret_provider`:
    ///
    /// returns: Server<S>
    ///
    /// # Examples
    ///
    /// ```
    ///
    /// ```
    pub fn set_secret_provider(mut self, secret_provider: S) -> Server<S> {
        self.secret_provider = secret_provider;
        self
    }

    /// **Required**
    ///
    /// Sets allowed hosts, from where Server would be allowed to accept RADIUS requests
    pub fn set_allowed_hosts(mut self, allowed_hosts: Vec<String>) -> Server<S> {
        self.allowed_hosts = allowed_hosts;
        self
    }

    /// **Required/Optional**
    ///
    /// Sets remote port, that responsible for specific RADIUS Message Type
    pub fn set_port(mut self, msg_type: RadiusMsgType, port: u16) -> Server<S> {
        self.host.set_port(msg_type, port);
        self
    }

    /// **Optional**
    ///
    /// Sets socket retries, otherwise you would have a default value of 1
    pub fn set_retries(mut self, retries: u16) -> Server<S> {
        self.retries = retries;
        self
    }

    /// **Optional**
    ///
    /// Sets socket timeout, otherwise you would have a default value of 2
    pub fn set_timeout(mut self, timeout: u16) -> Server<S> {
        self.timeout = timeout;
        self
    }
    // ===================

    /// Returns port of RADIUS server, that receives given type of RADIUS message/packet
    pub fn port(&self, code: &TypeCode) -> Option<u16> {
        self.host.port(code)
    }

    /// Returns hostname/FQDN of RADIUS Server
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Returns retries
    pub fn retries(&self) -> u16 {
        self.retries
    }

    /// Returns timeout
    pub fn timeout(&self) -> u16 {
        self.timeout
    }

    /// Returns allowed hosts list
    pub fn allowed_hosts(&self) -> &[String] {
        &self.allowed_hosts
    }

    /// Creates RADIUS packet attribute by name, that is defined in dictionary file
    ///
    /// For example, see [Client](crate::client::client::Client::create_attribute_by_name)
    pub fn create_attribute_by_name(
        &self,
        attribute_name: &str,
        value: Vec<u8>,
    ) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_name(attribute_name, value)
    }

    /// Creates RADIUS packet attribute by id, that is defined in dictionary file
    ///
    /// For example, see [Client](crate::client::client::Client::create_attribute_by_id)
    pub fn create_attribute_by_id(
        &self,
        attribute_id: u8,
        value: Vec<u8>,
    ) -> Result<RadiusAttribute, RadiusError> {
        self.host.create_attribute_by_id(attribute_id, value)
    }

    /// Creates reply RADIUS packet
    ///
    /// Similar to [Client's create_packet()](crate::client::client::Client::create_packet), however also sets correct packet ID and authenticator
    pub fn create_reply_packet(
        &self,
        reply_code: TypeCode,
        ip_addr: &SocketAddr,
        attributes: Vec<RadiusAttribute>,
        request: &mut [u8],
    ) -> RadiusPacket {
        let mut reply_packet = RadiusPacket::initialise_packet(reply_code);
        reply_packet.set_attributes(attributes);

        // We can only create new authenticator after we set reply packet ID to the request's ID
        reply_packet.override_id(request[1]);

        let authenticator =
            self.create_reply_authenticator(ip_addr, &reply_packet.to_bytes(), &request[4..20]);
        reply_packet.override_authenticator(authenticator);

        reply_packet
    }

    fn create_reply_authenticator(
        &self,
        ip_addr: &SocketAddr,
        raw_reply_packet: &[u8],
        request_authenticator: &[u8],
    ) -> Vec<u8> {
        // We need to create authenticator as MD5 hash (similar to how client verifies server reply)
        let mut md5_hasher = Md5::new();
        let secret = match self.secret_provider.get_secret(ip_addr) {
            Some(secret) => secret,
            None => return Vec::new(), // If no secret is found, return empty authenticator
        };

        md5_hasher.update(&raw_reply_packet[0..4]); // Append reply's   type code, reply ID and reply length
        md5_hasher.update(&request_authenticator); // Append request's authenticator
        md5_hasher.update(&raw_reply_packet[20..]); // Append reply's   attributes
        md5_hasher.update(&secret); // Append server's  secret. Possibly it should be client's secret, which sould be stored together with allowed hostnames ?
                                    // ----------------

        md5_hasher.finalize().to_vec()
    }

    /// Verifies incoming RADIUS packet:
    ///
    /// Server would try to build RadiusPacket from raw bytes, and if it succeeds then packet is
    /// valid, otherwise would return RadiusError
    pub fn verify_request(&self, request: &[u8]) -> Result<(), RadiusError> {
        match RadiusPacket::initialise_packet_from_bytes(&self.host.dictionary(), request) {
            Err(err) => Err(err),
            _ => Ok(()),
        }
    }

    /// Verifies RadiusAttributes's values of incoming RADIUS packet:
    ///
    /// Server would try to build RadiusPacket from raw bytes, and then it would try to restore
    /// RadiusAttribute original value from bytes, based on the attribute data type, see [SupportedAttributeTypes](crate::protocol::dictionary::SupportedAttributeTypes)
    pub fn verify_request_attributes(&self, request: &[u8]) -> Result<(), RadiusError> {
        self.host.verify_packet_attributes(&request)
    }

    /// Initialises RadiusPacket from bytes
    ///
    /// Unlike [verify_request](Server::verify_request), on success this function would return
    /// RadiusPacket
    pub fn initialise_packet_from_bytes(
        &self,
        request: &[u8],
    ) -> Result<RadiusPacket, RadiusError> {
        self.host.initialise_packet_from_bytes(request)
    }

    /// Checks if host from where Server received RADIUS request is allowed host, meaning RADIUS
    /// Server can process such request
    pub fn host_allowed(&self, remote_host: &std::net::SocketAddr) -> bool {
        let remote_host_name = remote_host.to_string();
        let remote_host_name: Vec<&str> = remote_host_name.split(':').collect();

        self.allowed_hosts
            .iter()
            .any(|host| host == remote_host_name[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::secret_provider::DefaultSecretProvider;

    #[test]
    fn test_add_allowed_hosts_and_add_request_handler() {
        let dictionary = Dictionary::from_file("./dict_examples/integration_dict").unwrap();
        let server: Server<DefaultSecretProvider> =
            Server::<DefaultSecretProvider>::with_dictionary(dictionary)
                .set_server(String::from("0.0.0.0"))
                .set_allowed_hosts(vec![String::from("127.0.0.1")]);

        assert_eq!(server.allowed_hosts().len(), 1);
    }
}
