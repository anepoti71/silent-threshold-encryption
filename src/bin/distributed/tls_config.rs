use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore, ServerConfig};

/// Generate a self-signed certificate for testing/development purposes
pub fn generate_self_signed_cert(
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
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

    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let key =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or("No private key found in file")?;

    Ok((certs, key))
}

/// Load certificate(s) from a PEM file to use as trusted roots on the client
pub fn load_certs(
    cert_path: &str,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

/// Create TLS client configuration backed by the provided root certificates (certificate pinning)
pub fn create_client_config_with_roots(
    roots: Vec<CertificateDer<'static>>,
) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    if roots.is_empty() {
        return Err("No certificates provided for server pinning".into());
    }
    let mut root_store = RootCertStore::empty();
    for cert in roots {
        ensure_ca_certificate(&cert)?;
        root_store.add(cert)?;
    }

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

fn ensure_ca_certificate(cert: &CertificateDer<'_>) -> Result<(), Box<dyn std::error::Error>> {
    if !basic_constraints_ca_true(cert.as_ref())? {
        return Err(
            "Pinned certificate must be a CA certificate (basicConstraints CA=true). \
Provide the certificate authority that signed the coordinator's TLS certificate."
                .into(),
        );
    }
    Ok(())
}

fn basic_constraints_ca_true(der: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    const BASIC_CONSTRAINTS_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
    let mut idx = 0;
    while let Some(pos) = find_subsequence(&der[idx..], BASIC_CONSTRAINTS_OID) {
        let mut cursor = idx + pos + BASIC_CONSTRAINTS_OID.len();

        // Skip optional critical flag (BOOLEAN)
        if cursor < der.len() && der[cursor] == 0x01 {
            cursor += 1;
            let (len, consumed) = read_der_length(&der[cursor..])?;
            cursor += consumed + len;
        }

        // Next must be OCTET STRING containing BasicConstraints
        if cursor >= der.len() || der[cursor] != 0x04 {
            idx += pos + 1;
            continue;
        }
        cursor += 1;
        let (octet_len, consumed) = read_der_length(&der[cursor..])?;
        cursor += consumed;
        if cursor + octet_len > der.len() {
            return Err("Malformed BasicConstraints extension".into());
        }
        let ext = &der[cursor..cursor + octet_len];

        // Parse BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
        if ext.is_empty() || ext[0] != 0x30 {
            return Err("Malformed BasicConstraints value".into());
        }
        let mut inner = 1;
        let (seq_len, seq_consumed) = read_der_length(&ext[inner..])?;
        inner += seq_consumed;
        if seq_len == 0 || inner >= ext.len() {
            return Ok(false);
        }
        if ext[inner] != 0x01 {
            // No explicit boolean -> defaults to FALSE
            return Ok(false);
        }
        inner += 1;
        let (bool_len, bool_consumed) = read_der_length(&ext[inner..])?;
        inner += bool_consumed;
        if bool_len == 0 || inner + bool_len > ext.len() {
            return Err("Malformed BasicConstraints boolean".into());
        }
        let val = ext[inner];
        return Ok(val != 0x00);
    }
    Ok(false)
}

fn read_der_length(bytes: &[u8]) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    if bytes.is_empty() {
        return Err("Unexpected end of DER data".into());
    }
    let first = bytes[0];
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 || bytes.len() < 1 + num_bytes {
        return Err("Invalid DER length".into());
    }
    let mut len = 0usize;
    for &b in &bytes[1..=num_bytes] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + num_bytes))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
