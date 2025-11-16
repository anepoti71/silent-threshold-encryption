use std::ops::Mul;

use crate::error::SteError;
use crate::{kzg::PowersOfTau, setup::AggregateKey};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    PrimeGroup,
};
use ark_serialize::*;
use ark_std::{rand::RngCore, UniformRand, Zero};

/// Number of G1 elements in the sa1 proof array.
pub const SA1_SIZE: usize = 2;

/// Number of G2 elements in the sa2 proof array.
pub const SA2_SIZE: usize = 6;

/// Number of random scalar values used during encryption.
pub const ENCRYPTION_RANDOMNESS_SIZE: usize = 5;

/// A ciphertext in the silent threshold encryption scheme.
///
/// Contains the encrypted message key along with proof elements.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct Ciphertext<E: Pairing> {
    /// G2 element: gamma * H (where gamma is random)
    pub gamma_g2: E::G2,
    /// G1 elements for proof (size = SA1_SIZE)
    pub sa1: [E::G1; SA1_SIZE],
    /// G2 elements for proof (size = SA2_SIZE)
    pub sa2: [E::G2; SA2_SIZE],
    /// The encrypted key (pairing output)
    pub enc_key: PairingOutput<E>,
    /// The threshold value
    pub t: usize,
}

impl<E: Pairing> Ciphertext<E> {
    /// Creates a new ciphertext.
    ///
    /// # Arguments
    /// * `gamma_g2` - G2 element: gamma * H
    /// * `sa1` - SA1_SIZE G1 proof elements
    /// * `sa2` - SA2_SIZE G2 proof elements
    /// * `enc_key` - The encrypted key
    /// * `t` - The threshold
    pub fn new(
        gamma_g2: E::G2,
        sa1: [E::G1; SA1_SIZE],
        sa2: [E::G2; SA2_SIZE],
        enc_key: PairingOutput<E>,
        t: usize,
    ) -> Self {
        Ciphertext {
            gamma_g2,
            sa1,
            sa2,
            enc_key,
            t,
        }
    }
}

/// Encrypts a message key using the aggregate public key.
///
/// # Arguments
/// * `apk` - The aggregate public key
/// * `t` - The threshold (must be < number of parties)
/// * `params` - The KZG parameters (powers of tau)
/// * `rng` - A random number generator
///
/// # Errors
/// Returns an error if t >= n, t + 1 exceeds params length, or other validation fails
pub fn encrypt<E: Pairing, R: RngCore>(
    apk: &AggregateKey<E>,
    t: usize,
    params: &PowersOfTau<E>,
    rng: &mut R,
) -> Result<Ciphertext<E>, SteError> {
    let n = apk.pk.len();
    
    // Validate inputs
    if n == 0 {
        return Err(SteError::ValidationError(
            "number of parties must be at least 1".to_string()
        ));
    }
    if t == 0 {
        return Err(SteError::ValidationError(
            "threshold must be at least 1".to_string()
        ));
    }
    if t >= n {
        return Err(SteError::ValidationError(
            format!("threshold ({}) must be < number of parties ({})", t, n)
        ));
    }
    if t + 1 > params.powers_of_g.len() {
        return Err(SteError::ValidationError(
            format!("t + 1 ({}) exceeds KZG parameters length ({})", t + 1, params.powers_of_g.len())
        ));
    }
    let gamma = E::ScalarField::rand(rng);
    let gamma_g2 = params.powers_of_h[0] * gamma;

    let g = params.powers_of_g[0];
    let h = params.powers_of_h[0];

    let mut sa1 = [E::G1::generator(); SA1_SIZE];
    let mut sa2 = [E::G2::generator(); SA2_SIZE];

    let mut s: [E::ScalarField; ENCRYPTION_RANDOMNESS_SIZE] = [E::ScalarField::zero(); ENCRYPTION_RANDOMNESS_SIZE];

    s.iter_mut()
        .for_each(|s_elem| *s_elem = E::ScalarField::rand(rng));

    // sa1[0] = s0*ask + s3*g^{tau^{t+1}} + s4*g
    sa1[0] = (apk.ask * s[0]) + (params.powers_of_g[t + 1] * s[3]) + (params.powers_of_g[0] * s[4]);

    // sa1[1] = s2*g
    sa1[1] = g * s[2];

    // sa2[0] = s0*h + s2*gamma_g2
    sa2[0] = (h * s[0]) + (gamma_g2 * s[2]);

    // sa2[1] = s0*z_g2
    sa2[1] = apk.z_g2 * s[0];

    // sa2[2] = s0*h^tau + s1*h^tau
    sa2[2] = params.powers_of_h[1] * (s[0] + s[1]);

    // sa2[3] = s1*h
    sa2[3] = h * s[1];

    // sa2[4] = s3*h
    sa2[4] = h * s[3];

    // sa2[5] = s4*h^{tau - omega^0}
    sa2[5] = (params.powers_of_h[1] + apk.h_minus1) * s[4];

    // enc_key = s4*e_gh
    let enc_key = apk.e_gh.mul(s[4]);

    Ok(Ciphertext {
        gamma_g2,
        sa1,
        sa2,
        enc_key,
        t,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kzg::KZG10,
        setup::{PublicKey, SecretKey},
    };
    use ark_poly::univariate::DensePolynomial;
    use ark_std::UniformRand;

    type E = ark_bls12_381::Bls12_381;
    type G1 = <E as Pairing>::G1;
    type G2 = <E as Pairing>::G2;
    type Fr = <E as Pairing>::ScalarField;
    type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

    #[test]
    fn test_encryption() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let tau = Fr::rand(&mut rng);
        let params = KZG10::<E, UniPoly381>::setup(n, tau).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(i, &params, n).unwrap())
        }

        let ak = AggregateKey::<E>::new(pk, &params).unwrap();
        let ct = encrypt::<E, _>(&ak, 2, &params, &mut rng).unwrap();

        let mut ct_bytes = Vec::new();
        ct.serialize_compressed(&mut ct_bytes).unwrap();
        println!("Compressed ciphertext: {} bytes", ct_bytes.len());

        let mut g1_bytes = Vec::new();
        let mut g2_bytes = Vec::new();
        let mut e_gh_bytes = Vec::new();

        let g = G1::generator();
        let h = G2::generator();

        g.serialize_compressed(&mut g1_bytes).unwrap();
        h.serialize_compressed(&mut g2_bytes).unwrap();
        ak.e_gh.serialize_compressed(&mut e_gh_bytes).unwrap();

        println!("G1 len: {} bytes", g1_bytes.len());
        println!("G2 len: {} bytes", g2_bytes.len());
        println!("GT len: {} bytes", e_gh_bytes.len());
    }
}
