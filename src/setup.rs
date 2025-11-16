use ark_ec::pairing::PairingOutput;
use crate::encryption::Ciphertext;
use crate::error::SteError;
use crate::kzg::{PowersOfTau, KZG10};
use crate::utils::lagrange_poly;
use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::Field;
use ark_poly::{
    domain::EvaluationDomain, univariate::DensePolynomial, DenseUVPolynomial, Polynomial,
    Radix2EvaluationDomain,
};
use ark_serialize::*;
use ark_std::{rand::RngCore, One, UniformRand, Zero};
use rayon::prelude::*;
use std::ops::{Mul, Sub};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct LagrangePowers<E: Pairing> {
    pub li: Vec<E::G1>,
    pub li_minus0: Vec<E::G1>,
    pub li_x: Vec<E::G1>,
    pub li_lj_z: Vec<Vec<E::G1>>,
}

impl<E: Pairing> LagrangePowers<E> {
    /// Creates new Lagrange powers by preprocessing Lagrange polynomial evaluations.
    ///
    /// # Arguments
    /// * `tau` - The evaluation point (must be non-zero)
    /// * `n` - The number of parties (must be a power of 2)
    ///
    /// # Errors
    /// Returns an error if tau is zero or n is not a power of 2
    pub fn new(tau: E::ScalarField, n: usize) -> Result<Self, SteError> {
        // Validate inputs
        if n == 0 {
            return Err(SteError::InvalidParameter(
                "n must be at least 1".to_string()
            ));
        }
        if tau.is_zero() {
            return Err(SteError::InvalidParameter("tau cannot be zero".to_string()));
        }
        if !n.is_power_of_two() {
            return Err(SteError::InvalidParameter(
                format!("n must be a power of 2, got {}", n)
            ));
        }

        let mut li_evals: Vec<E::ScalarField> = vec![E::ScalarField::zero(); n];
        let mut li_evals_minus0: Vec<E::ScalarField> = vec![E::ScalarField::zero(); n];
        let mut li_evals_x: Vec<E::ScalarField> = vec![E::ScalarField::zero(); n];
        // Since tau is already validated to be non-zero, inverse should always succeed
        let tau_inv = tau.inverse()
            .expect("tau inverse should exist since tau was validated to be non-zero");
        for i in 0..n {
            let li = lagrange_poly(n, i);
            li_evals[i] = li.evaluate(&tau);

            li_evals_minus0[i] = li_evals[i] - li.coeffs[0];

            li_evals_x[i] = li_evals_minus0[i] * tau_inv;
        }

        let z_eval = tau.pow([n as u64]) - E::ScalarField::one();
        let z_eval_inv = z_eval.inverse()
            .ok_or_else(|| SteError::InvalidParameter("z_eval inverse computation failed".to_string()))?;

        let mut li = vec![E::G1::zero(); n];
        for i in 0..n {
            li[i] = E::G1::generator() * li_evals[i];
        }

        let mut li_minus0 = vec![E::G1::zero(); n];
        li_minus0.par_iter_mut().enumerate().for_each(|(i, elem)| {
            *elem = E::G1::generator() * li_evals_minus0[i];
        });

        let mut li_x = vec![E::G1::zero(); n];
        li_x.par_iter_mut().enumerate().for_each(|(i, elem)| {
            *elem = E::G1::generator() * li_evals_x[i];
        });

        let mut li_lj_z = vec![vec![E::G1::zero(); n]; n];
        li_lj_z.par_iter_mut().enumerate().for_each(|(i, row)| {
            row.par_iter_mut().enumerate().for_each(|(j, elem)| {
                *elem = if i == j {
                    E::G1::generator() * ((li_evals[i] * li_evals[i] - li_evals[i]) * z_eval_inv)
                } else {
                    E::G1::generator() * (li_evals[i] * li_evals[j] * z_eval_inv)
                }
            });
        });

        Ok(LagrangePowers {
            li,
            li_minus0,
            li_x,
            li_lj_z,
        })
    }
}

/// Secret key for a party in the threshold encryption scheme.
///
/// Each party holds a secret key that is used to generate partial decryptions.
/// Note: Party 0 is the "dummy party" whose secret key should be nullified
/// (set to 1) as it always participates in decryption.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    sk: E::ScalarField,
}

/// Public key for a party in the threshold encryption scheme.
///
/// Contains the BLS public key and precomputed hint values needed for
/// efficient threshold decryption.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Default, Debug)]
pub struct PublicKey<E: Pairing> {
    /// Party identifier (0-indexed)
    pub id: usize,
    /// BLS public key: sk * G1_generator
    pub bls_pk: E::G1,
    /// Precomputed hint: commitment to sk * li(x) where li is the Lagrange basis polynomial
    pub sk_li: E::G1,
    /// Precomputed hint: commitment to sk * (li(x) - li(0))
    pub sk_li_minus0: E::G1,
    /// Precomputed hints: commitments to sk * li(x) * lj(x) / z(x) for all j
    pub sk_li_lj_z: Vec<E::G1>,
    /// Precomputed hint: commitment to sk * (li(x) - li(0)) / x
    pub sk_li_x: E::G1,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct AggregateKey<E: Pairing> {
    pub pk: Vec<PublicKey<E>>,
    pub agg_sk_li_lj_z: Vec<E::G1>,
    pub ask: E::G1,
    pub z_g2: E::G2,

    //preprocessed values
    pub h_minus1: E::G2,
    pub e_gh: PairingOutput<E>,
}

impl<E: Pairing> PublicKey<E> {
    pub fn new(
        id: usize,
        bls_pk: E::G1,
        sk_li: E::G1,
        sk_li_minus0: E::G1,
        sk_li_lj_z: Vec<E::G1>,
        sk_li_x: E::G1,
    ) -> Self {
        PublicKey {
            id,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_lj_z,
            sk_li_x,
        }
    }
}

impl<E: Pairing> SecretKey<E> {
    /// Creates a new secret key with a random scalar.
    ///
    /// # Arguments
    /// * `rng` - A random number generator
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        SecretKey {
            sk: E::ScalarField::rand(rng),
        }
    }

    /// Nullifies the secret key by setting it to one.
    /// This is used for the dummy party (party 0) which always participates.
    pub fn nullify(&mut self) {
        self.sk = E::ScalarField::one()
    }

    /// Computes the public key using the slower method (quadratic time).
    ///
    /// **Note:** This method is slower than `lagrange_get_pk` as it recomputes
    /// Lagrange polynomials. Consider using `lagrange_get_pk` with preprocessed
    /// `LagrangePowers` for better performance.
    ///
    /// # Arguments
    /// * `id` - The party ID (must be < n)
    /// * `params` - The KZG parameters (powers of tau)
    /// * `n` - The number of parties (must be a power of 2)
    ///
    /// # Errors
    /// Returns an error if id >= n, n is not a power of 2, or KZG operations fail
    pub fn get_pk(&self, id: usize, params: &PowersOfTau<E>, n: usize) -> Result<PublicKey<E>, SteError> {
        // Validate inputs
        if id >= n {
            return Err(SteError::ValidationError(
                format!("id ({}) must be < n ({})", id, n)
            ));
        }
        if !n.is_power_of_two() {
            return Err(SteError::InvalidParameter(
                format!("n must be a power of 2, got {}", n)
            ));
        }

        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n)
            .ok_or_else(|| SteError::DomainError(
                format!("Failed to create domain for n = {} (must be a power of 2)", n)
            ))?;

        let li = lagrange_poly(n, id);

        let mut sk_li_lj_z = vec![];
        for j in 0..n {
            let num = if id == j {
                li.clone().mul(&li).sub(&li)
            } else {
                //cross-terms
                let l_j = lagrange_poly(n, j);
                l_j.mul(&li)
            };

            let f = num.divide_by_vanishing_poly(domain).0;
            let sk_times_f = &f * self.sk;

            let com = KZG10::commit_g1(params, &sk_times_f)?;
            sk_li_lj_z.push(com.into());
        }

        // Compute sk_li_x: commitment to (li(x) - li(0))/x * sk
        // The polynomial (li(x) - li(0))/x has coefficients li.coeffs[1..]
        // This matches the computation in LagrangePowers::new where we compute
        // (li(tau) - li(0))/tau
        let li_x_coeffs: Vec<_> = if li.coeffs.len() > 1 {
            li.coeffs[1..].to_vec()
        } else {
            vec![E::ScalarField::zero()]
        };
        let li_x_poly = DensePolynomial::from_coefficients_vec(li_x_coeffs);
        let sk_times_f = &li_x_poly * self.sk;
        let sk_li_x = KZG10::commit_g1(params, &sk_times_f)?;

        // Compute sk_li: commitment to li(x) * sk
        let mut f = &li * self.sk;
        let sk_li = KZG10::commit_g1(params, &f)?;

        // Compute sk_li_minus0: commitment to (li(x) - li(0)) * sk
        f.coeffs[0] = E::ScalarField::zero();
        let sk_li_minus0 = KZG10::commit_g1(params, &f)?;

        Ok(PublicKey {
            id,
            bls_pk: E::G1::generator() * self.sk,
            sk_li: sk_li.into(),
            sk_li_minus0: sk_li_minus0.into(),
            sk_li_lj_z,
            sk_li_x: sk_li_x.into(),
        })
    }

    /// Computes the public key using preprocessed Lagrange powers (linear time).
    ///
    /// This is the recommended method as it's more efficient than `get_pk`.
    ///
    /// # Arguments
    /// * `id` - The party ID (must be < n)
    /// * `params` - The preprocessed Lagrange powers
    /// * `n` - The number of parties
    ///
    /// # Errors
    /// Returns an error if id >= n
    pub fn lagrange_get_pk(&self, id: usize, params: &LagrangePowers<E>, n: usize) -> Result<PublicKey<E>, SteError> {
        // Validate inputs
        if id >= n {
            return Err(SteError::ValidationError(
                format!("id ({}) must be < n ({})", id, n)
            ));
        }
        let mut sk_li_lj_z = vec![];

        let sk_li = params.li[id] * self.sk;

        let sk_li_minus0 = params.li_minus0[id] * self.sk;

        let sk_li_x = params.li_x[id] * self.sk;

        for j in 0..n {
            sk_li_lj_z.push(params.li_lj_z[id][j] * self.sk);
        }

        Ok(PublicKey {
            id,
            bls_pk: E::G1::generator() * self.sk,
            sk_li,
            sk_li_minus0,
            sk_li_lj_z,
            sk_li_x,
        })
    }

    /// Computes a partial decryption of the ciphertext.
    ///
    /// This is essentially a BLS signature on `gamma_g2`.
    ///
    /// # Arguments
    /// * `ct` - The ciphertext to partially decrypt
    pub fn partial_decryption(&self, ct: &Ciphertext<E>) -> E::G2 {
        ct.gamma_g2 * self.sk
    }
}

impl<E: Pairing> AggregateKey<E> {
    /// Creates an aggregate key from a vector of public keys.
    ///
    /// # Arguments
    /// * `pk` - Vector of public keys (must not be empty)
    /// * `params` - The KZG parameters (powers of tau)
    ///
    /// # Errors
    /// Returns an error if pk is empty or if n > params length
    pub fn new(pk: Vec<PublicKey<E>>, params: &PowersOfTau<E>) -> Result<Self, SteError> {
        let n = pk.len();
        if n == 0 {
            return Err(SteError::ValidationError("pk cannot be empty".to_string()));
        }
        if n > params.powers_of_h.len() {
            return Err(SteError::ValidationError(
                format!("n ({}) exceeds KZG parameters length ({})", n, params.powers_of_h.len())
            ));
        }

        let h_minus1 = params.powers_of_h[0] * (-E::ScalarField::one());
        let z_g2 = params.powers_of_h[n] + h_minus1;

        // gather sk_li from all public keys
        let mut ask = E::G1::zero();
        for pki in pk.iter() {
            ask += pki.sk_li;
        }

        let mut agg_sk_li_lj_z = vec![];
        for i in 0..n {
            let mut agg_sk_li_lj_zi = E::G1::zero();
            for pkj in pk.iter() {
                agg_sk_li_lj_zi += pkj.sk_li_lj_z[i];
            }
            agg_sk_li_lj_z.push(agg_sk_li_lj_zi);
        }

        Ok(AggregateKey {
            pk,
            agg_sk_li_lj_z,
            ask,
            z_g2,
            h_minus1,
            e_gh: E::pairing(params.powers_of_g[0], params.powers_of_h[0]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type E = ark_bls12_381::Bls12_381;
    type Fr = <E as Pairing>::ScalarField;
    type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

    #[test]
    fn test_setup() {
        let mut rng = ark_std::test_rng();
        let n = 16;
        let tau = Fr::rand(&mut rng);
        let params = KZG10::<E, UniPoly381>::setup(n, tau).unwrap();
        let lagrange_params = LagrangePowers::<E>::new(tau, n).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();
        let mut lagrange_pk: Vec<PublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(i, &params, n).unwrap());
            lagrange_pk.push(sk[i].lagrange_get_pk(i, &lagrange_params, n).unwrap());

            assert_eq!(pk[i].sk_li, lagrange_pk[i].sk_li);
            assert_eq!(pk[i].sk_li_minus0, lagrange_pk[i].sk_li_minus0);
            assert_eq!(pk[i].sk_li_x, lagrange_pk[i].sk_li_x, "sk_li_x mismatch for party {}", i);
            assert_eq!(pk[i].sk_li_lj_z, lagrange_pk[i].sk_li_lj_z);
        }

        let _ak = AggregateKey::<E>::new(pk, &params).unwrap();
    }
}
