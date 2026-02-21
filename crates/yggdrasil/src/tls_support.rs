use ed25519_dalek::SigningKey;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
pub fn generate_self_signed_cert(
    signing_key: &SigningKey,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, time::OffsetDateTime), String> {
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

    // Generate key pair and self-signed certificate
    let key_pair = KeyPair::generate()
        .map_err(|e| format!("failed to generate key pair: {}", e))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("failed to generate certificate: {}", e))?;

    // Get certificate DER
    let cert_der = cert.der().to_vec();

    // Get private key DER
    let private_key_der = key_pair.serialize_der();

    Ok((
        vec![CertificateDer::from(cert_der)],
        PrivateKeyDer::try_from(private_key_der)
            .map_err(|e| format!("failed to create private key: {:?}", e))?,
        not_after,
    ))
}

/// Create TLS server configuration that accepts all client certificates.
/// This uses TLS 1.3 only for maximum security (matching Go implementation).
pub fn create_server_config(
    certs: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, String> {
    use rustls::version::TLS13;

    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| format!("failed to create server config: {}", e))?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| format!("failed to set certificate: {}", e))?;

    config.alpn_protocols = vec![];

    Ok(Arc::new(config))
}

/// Create TLS client configuration that accepts all server certificates.
/// This is safe because Yggdrasil uses its own handshake protocol for authentication.
/// Supports TLS 1.2 and 1.3 for compatibility (matching Go implementation).
pub fn create_client_config() -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls::version::{TLS12, TLS13};

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS12, &TLS13])
        .map_err(|e| format!("failed to create client config: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth();

    config.alpn_protocols = vec![];

    Ok(Arc::new(config))
}