use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::{self, ClientConfig, ServerConfig};

/// Generate a self-signed certificate for testing/development purposes
pub fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = PrivateKeyDer::try_from(cert.key_pair.serialize_der())?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());

    Ok((vec![cert_der], key))
}

/// Create TLS server configuration with the provided certificate and private key
pub fn create_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Create TLS client configuration that accepts self-signed certificates
/// WARNING: This is insecure and should only be used for development/testing
pub fn create_client_config_dev() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    // For development, we'll skip certificate verification
    // In production, you should add proper CA certificates to root_store
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Custom certificate verifier that accepts all certificates
/// WARNING: This is insecure and should only be used for development/testing
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Save certificate and key to PEM files
#[allow(dead_code)]
pub fn save_cert_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;

    std::fs::write(cert_path, cert.cert.pem())?;
    std::fs::write(key_path, cert.key_pair.serialize_pem())?;

    println!("✓ Certificate saved to: {}", cert_path);
    println!("✓ Private key saved to: {}", key_path);

    Ok(())
}

/// Load certificate and key from PEM files
#[allow(dead_code)]
pub fn load_cert_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let key_file = std::fs::File::open(key_path)?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or("No private key found in file")?;

    Ok((certs, key))
}
