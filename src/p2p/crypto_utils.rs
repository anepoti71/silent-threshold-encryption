//! Cryptographic utilities for message authentication in P2P protocol
//!
//! This module provides signing and verification utilities using Ed25519
//! signatures from libp2p identity keys. All P2P messages that contain
//! cryptographic material (public keys, partial decryptions) should be
//! signed to prevent spoofing attacks.

use blake2::{Blake2b512, Digest};
use libp2p::identity::{Keypair, PublicKey};

/// Error types for signature operations
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid signature format")]
    InvalidFormat,

    #[error("unsupported key type (only Ed25519 supported)")]
    UnsupportedKeyType,

    #[error("peer ID mismatch")]
    PeerIdMismatch,
}

/// Sign a message using the libp2p keypair
///
/// # Arguments
/// * `keypair` - The libp2p Ed25519 keypair
/// * `message` - The message bytes to sign
///
/// # Returns
/// Signature bytes (64 bytes for Ed25519)
pub fn sign_message(keypair: &Keypair, message: &[u8]) -> Result<Vec<u8>, SignatureError> {
    // Hash the message first for domain separation and fixed-size input
    let hash = hash_message(message);

    match keypair.sign(&hash) {
        Ok(signature) => Ok(signature),
        Err(e) => Err(SignatureError::VerificationFailed(format!(
            "signing failed: {:?}",
            e
        ))),
    }
}

/// Verify a message signature using the peer's public key
///
/// # Arguments
/// * `public_key` - The peer's libp2p public key
/// * `message` - The original message bytes
/// * `signature` - The signature bytes
///
/// # Returns
/// `Ok(())` if verification succeeds, otherwise error
pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    // Hash the message (same as signing)
    let hash = hash_message(message);

    // libp2p's verify returns bool, not Result
    if public_key.verify(&hash, signature) {
        Ok(())
    } else {
        Err(SignatureError::VerificationFailed(
            "signature does not match".into(),
        ))
    }
}

/// Sign cryptographic material (public key, partial decryption, etc.)
///
/// Creates a signature over:
/// - The peer_id (for binding)
/// - The party_id (for attribution)
/// - The cryptographic payload
///
/// This prevents replay attacks and ensures the signature is bound to
/// the specific peer and party.
pub fn sign_crypto_message(
    keypair: &Keypair,
    peer_id: &str,
    party_id: usize,
    payload: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    let mut message = Vec::new();
    message.extend_from_slice(peer_id.as_bytes());
    message.extend_from_slice(&party_id.to_le_bytes());
    message.extend_from_slice(payload);

    sign_message(keypair, &message)
}

/// Verify a signature on cryptographic material
///
/// Verifies that the signature matches the expected format:
/// sign(peer_id || party_id || payload)
pub fn verify_crypto_signature(
    public_key: &PublicKey,
    peer_id: &str,
    party_id: usize,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), SignatureError> {
    let mut message = Vec::new();
    message.extend_from_slice(peer_id.as_bytes());
    message.extend_from_slice(&party_id.to_le_bytes());
    message.extend_from_slice(payload);

    verify_signature(public_key, &message, signature)
}

/// Convert a peer_id string to a libp2p PublicKey
///
/// Note: For modern PeerIds (using Ed25519 identity hashes), the public key
/// is embedded in the PeerId itself and can be extracted.
/// For older/different formats, this may fail and you should store the
/// public key separately when peers announce themselves.
pub fn peer_id_to_public_key(peer_id: &str) -> Result<PublicKey, SignatureError> {
    use libp2p::PeerId;

    let peer_id: PeerId = peer_id
        .parse()
        .map_err(|_| SignatureError::InvalidFormat)?;

    // For Ed25519 keys, libp2p encodes the key directly in the PeerId (identity hash)
    // We can extract it using the multihash
    let multihash = peer_id.as_ref();

    // Check if it's an identity multihash (code 0x00)
    if multihash.code() == 0x00 {
        // For identity hash, the digest is the actual public key
        let key_bytes = multihash.digest();
        PublicKey::try_decode_protobuf(key_bytes)
            .map_err(|_| SignatureError::UnsupportedKeyType)
    } else {
        // For other hash types, we cannot recover the public key
        Err(SignatureError::UnsupportedKeyType)
    }
}

/// Hash a message using Blake2b-512 (for domain separation)
fn hash_message(message: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(b"silent-threshold-p2p-v1:");
    hasher.update(message);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate_ed25519();
        let message = b"test message";

        let signature = sign_message(&keypair, message).unwrap();
        let public_key = keypair.public();

        assert!(verify_signature(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let keypair = Keypair::generate_ed25519();
        let message1 = b"test message";
        let message2 = b"different message";

        let signature = sign_message(&keypair, message1).unwrap();
        let public_key = keypair.public();

        assert!(verify_signature(&public_key, message2, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let keypair1 = Keypair::generate_ed25519();
        let keypair2 = Keypair::generate_ed25519();
        let message = b"test message";

        let signature = sign_message(&keypair1, message).unwrap();
        let public_key2 = keypair2.public();

        assert!(verify_signature(&public_key2, message, &signature).is_err());
    }

    #[test]
    fn test_sign_crypto_message() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = libp2p::PeerId::from(keypair.public()).to_string();
        let party_id = 42;
        let payload = b"public key bytes";

        let signature = sign_crypto_message(&keypair, &peer_id, party_id, payload).unwrap();
        let public_key = keypair.public();

        assert!(verify_crypto_signature(&public_key, &peer_id, party_id, payload, &signature).is_ok());
    }

    #[test]
    fn test_verify_crypto_wrong_party_id_fails() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = libp2p::PeerId::from(keypair.public()).to_string();
        let party_id = 42;
        let payload = b"public key bytes";

        let signature = sign_crypto_message(&keypair, &peer_id, party_id, payload).unwrap();
        let public_key = keypair.public();

        // Wrong party ID should fail
        assert!(verify_crypto_signature(&public_key, &peer_id, 43, payload, &signature).is_err());
    }

    #[test]
    fn test_peer_id_round_trip() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = libp2p::PeerId::from(keypair.public()).to_string();

        let recovered_pubkey = peer_id_to_public_key(&peer_id).unwrap();
        assert_eq!(keypair.public(), recovered_pubkey);
    }
}
