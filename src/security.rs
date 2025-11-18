//! Security utilities for protecting sensitive cryptographic data
//!
//! This module provides:
//! - Memory protection traits for sensitive data
//! - Constant-time comparison operations
//! - Zeroization helpers for arkworks types

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};
use ark_std::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wrapper for sensitive scalar field elements that ensures zeroization on drop
///
/// This wrapper provides memory protection for cryptographic secrets like
/// private keys, random nonces, and other sensitive scalar values.
///
/// # Security
/// - Automatically zeroizes memory when dropped
/// - Provides constant-time equality comparison
/// - Prevents accidental leakage through Debug trait
#[derive(Clone)]
pub struct SensitiveScalar<F: Field> {
    value: F,
}

impl<F: Field> SensitiveScalar<F> {
    /// Create a new sensitive scalar from a field element
    pub fn new(value: F) -> Self {
        Self { value }
    }

    /// Get a reference to the inner value
    ///
    /// # Security Warning
    /// The caller must ensure this reference is not used to leak the value
    pub fn expose_secret(&self) -> &F {
        &self.value
    }

    /// Convert into the inner value
    ///
    /// # Security Warning
    /// The caller is responsible for properly zeroizing the returned value
    pub fn into_inner(self) -> F {
        self.value
    }

    /// Create a new sensitive scalar with value zero
    pub fn zero() -> Self {
        Self { value: F::zero() }
    }

    /// Create a new sensitive scalar with value one
    pub fn one() -> Self {
        Self { value: F::one() }
    }
}

impl<F: Field> Zeroize for SensitiveScalar<F> {
    fn zeroize(&mut self) {
        // Overwrite with zero value
        self.value = F::zero();

        // For extra security, we could also overwrite the memory directly
        // However, arkworks field elements may use internal representations
        // that don't expose raw bytes, so we rely on setting to zero
    }
}

impl<F: Field> ZeroizeOnDrop for SensitiveScalar<F> {}

impl<F: Field> Drop for SensitiveScalar<F> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<F> CanonicalSerialize for SensitiveScalar<F>
where
    F: Field + CanonicalSerialize,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.value.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.value.serialized_size(compress)
    }
}

impl<F> CanonicalDeserialize for SensitiveScalar<F>
where
    F: Field + CanonicalDeserialize,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let value = F::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(SensitiveScalar::new(value))
    }
}

impl<F> Valid for SensitiveScalar<F>
where
    F: Field + Valid,
{
    fn check(&self) -> Result<(), SerializationError> {
        self.value.check()
    }
}

// Prevent debug output from leaking sensitive data
impl<F: Field> std::fmt::Debug for SensitiveScalar<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SensitiveScalar([REDACTED])")
    }
}

/// Constant-time equality comparison for field elements
///
/// This function attempts to perform constant-time comparison to prevent
/// timing attacks when comparing secret values.
///
/// # Security Note
/// While we attempt constant-time comparison, the underlying field operations
/// from arkworks may not be constant-time. This provides defense-in-depth
/// but should not be relied upon as the sole timing attack mitigation.
pub fn constant_time_eq<F: Field>(a: &F, b: &F) -> bool {
    // Convert to bytes and use constant-time comparison
    // Note: This assumes that serialization is deterministic
    let mut a_bytes = Vec::new();
    let mut b_bytes = Vec::new();

    // If serialization fails, treat as not equal
    if a.serialize_compressed(&mut a_bytes).is_err() {
        return false;
    }
    if b.serialize_compressed(&mut b_bytes).is_err() {
        return false;
    }

    // Check length first (this is fine to leak)
    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    // Constant-time byte comparison
    subtle_constant_time_eq(&a_bytes, &b_bytes)
}

/// Constant-time byte slice comparison
///
/// Returns true if slices are equal, false otherwise.
/// Assumes slices have the same length (caller must check).
fn subtle_constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Verify BLS signature in constant-time
///
/// This function verifies a BLS signature by checking if the partial decryption
/// was computed correctly. While the pairing operation itself may not be
/// constant-time, we ensure the final comparison is constant-time to prevent
/// timing attacks on the signature verification.
///
/// # Arguments
/// * `signature` - The signature (partial decryption) to verify
/// * `public_key` - The public key of the signer
/// * `message` - The message (gamma_g2) that was signed
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
pub fn verify_bls_signature_ct<E: Pairing>(
    signature: &E::G2,
    public_key: &E::G1,
    message: &E::G2,
) -> bool {
    use ark_ec::PrimeGroup;

    // Compute e(pk, message) and e(G1, signature)
    // Valid signature satisfies: e(G1, signature) == e(pk, message)
    let lhs = E::pairing(E::G1::generator(), *signature);
    let rhs = E::pairing(*public_key, *message);

    // Use constant-time comparison for the final check
    constant_time_eq_pairing(&lhs, &rhs)
}

/// Constant-time equality comparison for pairing outputs
///
/// Compares two pairing outputs in constant time.
pub fn constant_time_eq_pairing<E: Pairing>(
    a: &ark_ec::pairing::PairingOutput<E>,
    b: &ark_ec::pairing::PairingOutput<E>,
) -> bool {
    use ark_serialize::CanonicalSerialize;

    let mut a_bytes = Vec::new();
    let mut b_bytes = Vec::new();

    if a.serialize_compressed(&mut a_bytes).is_err() {
        return false;
    }
    if b.serialize_compressed(&mut b_bytes).is_err() {
        return false;
    }

    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    subtle_constant_time_eq(&a_bytes, &b_bytes)
}

/// Constant-time equality comparison for pairing group elements
///
/// Compares two group elements in constant time by serializing and
/// comparing their byte representations.
pub fn constant_time_eq_g1<E: Pairing>(a: &E::G1, b: &E::G1) -> bool {
    use ark_serialize::CanonicalSerialize;

    let mut a_bytes = Vec::new();
    let mut b_bytes = Vec::new();

    if a.serialize_compressed(&mut a_bytes).is_err() {
        return false;
    }
    if b.serialize_compressed(&mut b_bytes).is_err() {
        return false;
    }

    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    subtle_constant_time_eq(&a_bytes, &b_bytes)
}

/// Constant-time equality comparison for G2 elements
pub fn constant_time_eq_g2<E: Pairing>(a: &E::G2, b: &E::G2) -> bool {
    use ark_serialize::CanonicalSerialize;

    let mut a_bytes = Vec::new();
    let mut b_bytes = Vec::new();

    if a.serialize_compressed(&mut a_bytes).is_err() {
        return false;
    }
    if b.serialize_compressed(&mut b_bytes).is_err() {
        return false;
    }

    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    subtle_constant_time_eq(&a_bytes, &b_bytes)
}

/// Wrapper for vectors containing sensitive data
///
/// Ensures that all elements are zeroized when the vector is dropped
#[derive(Clone)]
pub struct SensitiveVec<T: Zeroize> {
    inner: Vec<T>,
}

impl<T: Zeroize> SensitiveVec<T> {
    /// Create a new sensitive vector
    pub fn new(inner: Vec<T>) -> Self {
        Self { inner }
    }

    /// Get a reference to the inner vector
    pub fn expose_secret(&self) -> &Vec<T> {
        &self.inner
    }

    /// Get a mutable reference to the inner vector
    pub fn expose_secret_mut(&mut self) -> &mut Vec<T> {
        &mut self.inner
    }

    /// Convert into the inner vector
    ///
    /// # Safety
    /// This method consumes self and returns the inner vector.
    /// The caller is responsible for properly zeroizing the returned vector.
    pub fn into_inner(mut self) -> Vec<T> {
        // Temporarily replace with empty vec to avoid double-drop
        let inner = std::mem::take(&mut self.inner);
        // Forget self to prevent Drop from running
        std::mem::forget(self);
        inner
    }

    /// Get the length of the vector
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the vector is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<T: Zeroize> Zeroize for SensitiveVec<T> {
    fn zeroize(&mut self) {
        self.inner.iter_mut().for_each(|item| item.zeroize());
        self.inner.clear();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for SensitiveVec<T> {}

impl<T: Zeroize> Drop for SensitiveVec<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: Zeroize> std::fmt::Debug for SensitiveVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SensitiveVec")
            .field("len", &self.inner.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::UniformRand;

    #[test]
    fn test_sensitive_scalar_zeroization() {
        use ark_std::{UniformRand, Zero};
        let mut rng = ark_std::test_rng();
        let secret = Fr::rand(&mut rng);

        let mut sensitive = SensitiveScalar::new(secret);
        assert_eq!(sensitive.expose_secret(), &secret);

        // Zeroize
        sensitive.zeroize();
        assert_eq!(sensitive.expose_secret(), &Fr::zero());
    }

    #[test]
    fn test_sensitive_scalar_drop() {
        use ark_std::UniformRand;
        let mut rng = ark_std::test_rng();
        let secret = Fr::rand(&mut rng);

        {
            let _sensitive = SensitiveScalar::new(secret);
            // Should be zeroized when it goes out of scope
        }

        // We can't directly verify zeroization after drop,
        // but we can verify the zeroize method works
    }

    #[test]
    fn test_constant_time_eq() {
        let mut rng = ark_std::test_rng();
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);

        // Same values should be equal
        assert!(constant_time_eq(&a, &a));
        assert!(constant_time_eq(&b, &b));

        // Different values should not be equal
        // (unless we got incredibly lucky with random generation)
        if a != b {
            assert!(!constant_time_eq(&a, &b));
        }
    }

    #[test]
    fn test_sensitive_vec() {
        let mut vec = SensitiveVec::new(vec![
            SensitiveScalar::new(Fr::from(1u64)),
            SensitiveScalar::new(Fr::from(2u64)),
            SensitiveScalar::new(Fr::from(3u64)),
        ]);

        assert_eq!(vec.len(), 3);
        assert!(!vec.is_empty());

        vec.zeroize();
        assert_eq!(vec.len(), 0);
        assert!(vec.is_empty());
    }

    #[test]
    fn test_subtle_constant_time_eq() {
        let a = vec![1u8, 2, 3, 4];
        let b = vec![1u8, 2, 3, 4];
        let c = vec![1u8, 2, 3, 5];

        assert!(super::subtle_constant_time_eq(&a, &b));
        assert!(!super::subtle_constant_time_eq(&a, &c));
    }

    #[test]
    fn test_constant_time_eq_g1() {
        use ark_bls12_381::Bls12_381;
        use ark_ec::{AdditiveGroup, PrimeGroup};

        type E = Bls12_381;
        type G1 = <E as ark_ec::pairing::Pairing>::G1;

        let g1 = G1::generator();
        let g1_double = g1.double();

        // Same elements should be equal
        assert!(constant_time_eq_g1::<E>(&g1, &g1));
        assert!(constant_time_eq_g1::<E>(&g1_double, &g1_double));

        // Different elements should not be equal
        assert!(!constant_time_eq_g1::<E>(&g1, &g1_double));
    }

    #[test]
    fn test_constant_time_eq_g2() {
        use ark_bls12_381::Bls12_381;
        use ark_ec::{AdditiveGroup, PrimeGroup};

        type E = Bls12_381;
        type G2 = <E as ark_ec::pairing::Pairing>::G2;

        let g2 = G2::generator();
        let g2_double = g2.double();

        // Same elements should be equal
        assert!(constant_time_eq_g2::<E>(&g2, &g2));
        assert!(constant_time_eq_g2::<E>(&g2_double, &g2_double));

        // Different elements should not be equal
        assert!(!constant_time_eq_g2::<E>(&g2, &g2_double));
    }

    #[test]
    fn test_verify_bls_signature_ct() {
        use ark_bls12_381::Bls12_381;
        use ark_ec::pairing::Pairing;
        use ark_ec::PrimeGroup;
        use ark_std::UniformRand;

        type E = Bls12_381;
        type Fr = <E as Pairing>::ScalarField;
        type G1 = <E as Pairing>::G1;
        type G2 = <E as Pairing>::G2;

        let mut rng = ark_std::test_rng();

        // Generate a secret key and public key
        let sk = Fr::rand(&mut rng);
        let pk = G1::generator() * sk;

        // Generate a message
        let message = G2::rand(&mut rng);

        // Create a valid signature: signature = sk * message
        let valid_signature = message * sk;

        // Create an invalid signature
        let invalid_signature = message * Fr::rand(&mut rng);

        // Test valid signature verification
        assert!(verify_bls_signature_ct::<E>(
            &valid_signature,
            &pk,
            &message
        ));

        // Test invalid signature verification
        assert!(!verify_bls_signature_ct::<E>(
            &invalid_signature,
            &pk,
            &message
        ));
    }

    #[test]
    fn test_constant_time_eq_pairing() {
        use ark_bls12_381::Bls12_381;
        use ark_ec::pairing::Pairing;
        use ark_std::UniformRand;

        type E = Bls12_381;
        type G1 = <E as Pairing>::G1;
        type G2 = <E as Pairing>::G2;

        let mut rng = ark_std::test_rng();

        let g1 = G1::rand(&mut rng);
        let g2 = G2::rand(&mut rng);

        let pairing1 = E::pairing(g1, g2);
        let pairing2 = E::pairing(g1, g2);
        let pairing3 = E::pairing(G1::rand(&mut rng), g2);

        // Same pairings should be equal
        assert!(constant_time_eq_pairing::<E>(&pairing1, &pairing2));

        // Different pairings should not be equal
        assert!(!constant_time_eq_pairing::<E>(&pairing1, &pairing3));
    }

    #[test]
    fn test_sensitive_scalar_debug() {
        use ark_bls12_381::Fr;
        use ark_std::UniformRand;

        let mut rng = ark_std::test_rng();
        let secret = Fr::rand(&mut rng);
        let sensitive = SensitiveScalar::new(secret);

        // Debug output should not reveal the secret
        let debug_str = format!("{:?}", sensitive);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&format!("{:?}", secret)));
    }
}
