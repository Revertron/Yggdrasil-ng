use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use std::sync::Arc;

/// Custom certificate verifier that accepts all certificates.
/// This is safe because Yggdrasil uses its own handshake protocol for authentication.
#[derive(Debug)]
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Generate a self-signed TLS certificate.
/// The certificate is only used for the TLS handshake; actual authentication
/// happens at the Yggdrasil protocol level, so we don't need to embed the
/// Ed25519 key in the certificate.
/// Returns (certificate chain, private key, expiry time).
/// Generated TLS certificate material (raw DER bytes).
/// Can be cloned to create both server and client configs.
pub struct TlsCertMaterial {
    pub cert_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub expiry: time::OffsetDateTime,
}

impl TlsCertMaterial {
    /// Create a certificate chain suitable for rustls.
    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.cert_der.clone())]
    }

    /// Create a private key suitable for rustls.
    pub fn private_key(&self) -> Result<PrivateKeyDer<'static>, String> {
        PrivateKeyDer::try_from(self.private_key_der.clone())
            .map_err(|e| format!("failed to create private key: {:?}", e))
    }
}

pub fn generate_self_signed_cert(
    signing_key: &SigningKey,
) -> Result<TlsCertMaterial, String> {
    let identity = hex::encode(signing_key.verifying_key().as_bytes());
    // Generate a simple self-signed certificate using rcgen defaults
    // We use ECDSA P-256 as it's widely supported and efficient
    let mut params = CertificateParams::new(vec![identity])
        .map_err(|e| format!("failed to create params: {}", e))?;

    // Set validity period to mimic Let's Encrypt certificates (90 days total):
    // - NotBefore: current time minus 15 days (cert is 15 days old)
    // - NotAfter: current time plus 75 days (expires in 75 days)
    // This looks much more legitimate than a never-expiring self-signed cert
    let now = time::OffsetDateTime::now_utc();
    let not_before = now - time::Duration::days(15);
    let not_after = now + time::Duration::days(75);

    params.not_before = time::OffsetDateTime::new_utc(
        time::Date::from_calendar_date(not_before.year(), not_before.month(), not_before.day())
            .map_err(|e| format!("invalid date: {}", e))?,
        time::Time::from_hms(not_before.hour(), not_before.minute(), not_before.second())
            .map_err(|e| format!("invalid time: {}", e))?,
    );
    params.not_after = time::OffsetDateTime::new_utc(
        time::Date::from_calendar_date(not_after.year(), not_after.month(), not_after.day())
            .map_err(|e| format!("invalid date: {}", e))?,
        time::Time::from_hms(not_after.hour(), not_after.minute(), not_after.second())
            .map_err(|e| format!("invalid time: {}", e))?,
    );

    // Convert the node's ed25519 signing key to PKCS#8 DER for use with rcgen
    let pkcs8_doc = signing_key
        .to_pkcs8_der()
        .map_err(|e| format!("failed to encode signing key as PKCS#8: {}", e))?;
    let pkcs8_key = PrivatePkcs8KeyDer::from(pkcs8_doc.as_bytes().to_vec());

    // Create rcgen KeyPair from the node's ed25519 key
    let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_key, &rcgen::PKCS_ED25519)
        .map_err(|e| format!("failed to create key pair from signing key: {}", e))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("failed to generate certificate: {}", e))?;

    // Get certificate DER
    let cert_der = cert.der().to_vec();

    // Get private key DER
    let private_key_der = key_pair.serialize_der();

    Ok(TlsCertMaterial {
        cert_der,
        private_key_der,
        expiry: not_after,
    })
}

/// Extract the 32-byte ed25519 public key from a DER-encoded X.509 certificate.
/// Returns `None` if the certificate does not contain an ed25519 key or cannot be parsed.
pub fn extract_ed25519_pubkey_from_cert(cert_der: &[u8]) -> Option<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let spki = &cert.tbs_certificate.subject_pki;

    // OID 1.3.101.112 = id-Ed25519
    let ed25519_oid = x509_parser::oid_registry::Oid::from(&[1, 3, 101, 112]).ok()?;
    if spki.algorithm.algorithm != ed25519_oid {
        return None;
    }

    let key_bytes: &[u8] = &spki.subject_public_key.data;
    if key_bytes.len() != 32 {
        return None;
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(key_bytes);
    Some(key)
}

/// Custom client certificate verifier that accepts all client certificates.
/// Actual verification happens post-handshake by cross-checking with the meta handshake.
#[derive(Debug)]
struct AcceptAllClientVerifier;

impl rustls::server::danger::ClientCertVerifier for AcceptAllClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false // Optional: if client doesn't send a cert, connection still succeeds
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Create TLS server configuration with optional client certificate authentication.
/// This uses TLS 1.3 only for maximum security (matching Go implementation).
pub fn create_server_config(
    certs: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, String> {
    use rustls::version::TLS13;

    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| format!("failed to create server config: {}", e))?
        .with_client_cert_verifier(Arc::new(AcceptAllClientVerifier))
        .with_single_cert(certs, private_key)
        .map_err(|e| format!("failed to set certificate: {}", e))?;

    config.alpn_protocols = vec![];

    Ok(Arc::new(config))
}

/// Create TLS client configuration that accepts all server certificates
/// and sends our certificate for mutual TLS authentication.
/// Supports TLS 1.2 and 1.3 for compatibility (matching Go implementation).
pub fn create_client_config(
    certs: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls::version::{TLS12, TLS13};

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS12, &TLS13])
        .map_err(|e| format!("failed to create client config: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_client_auth_cert(certs, private_key)
        .map_err(|e| format!("failed to set client certificate: {}", e))?;

    config.alpn_protocols = vec![];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_ed25519_cert_contains_node_pubkey() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let expected_pubkey = signing_key.verifying_key().to_bytes();

        let material = generate_self_signed_cert(&signing_key).unwrap();
        let certs = material.cert_chain();
        assert_eq!(certs.len(), 1);

        let extracted = extract_ed25519_pubkey_from_cert(certs[0].as_ref())
            .expect("should extract ed25519 pubkey from cert");
        assert_eq!(extracted, expected_pubkey);
    }

    #[test]
    fn test_extract_from_non_ed25519_cert_returns_none() {
        // Generate a cert with a random ECDSA P-256 key (the old behavior)
        let mut params = CertificateParams::new(vec!["test".to_string()]).unwrap();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);

        let key_pair = KeyPair::generate().unwrap(); // ECDSA P-256
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().as_ref();

        let result = extract_ed25519_pubkey_from_cert(cert_der);
        assert!(result.is_none(), "ECDSA cert should not yield an ed25519 pubkey");
    }
}