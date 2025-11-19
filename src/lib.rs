//! Silent Threshold Encryption
//!
//! This library implements the silent threshold encryption scheme described in
//! [ePrint:2024/263](https://eprint.iacr.org/2024/263).
//!
//! ## Overview
//!
//! Silent threshold encryption allows encrypting a message to a group of parties
//! such that decryption requires at least `t` out of `n` parties to participate.
//! The scheme is "silent" in that the public keys don't reveal the threshold structure.
//!
//! ## Key Components
//!
//! - **Setup**: Generate KZG parameters and preprocess Lagrange polynomial evaluations
//! - **Key Generation**: Generate secret/public key pairs for each party
//! - **Encryption**: Encrypt a message key using the aggregate public key
//! - **Decryption**: Aggregate partial decryptions from participating parties
//!
//! ## Example
//!
//! ```rust,no_run
//! use ark_bls12_381::Bls12_381;
//! use ark_poly::univariate::DensePolynomial;
//! use ark_std::{UniformRand, Zero};
//! use silent_threshold_encryption::{
//!     setup::{SecretKey, LagrangePowers, AggregateKey},
//!     encryption::encrypt,
//!     decryption::agg_dec,
//!     kzg::KZG10,
//! };
//!
//! type E = Bls12_381;
//! type UniPoly = DensePolynomial<<E as ark_ec::pairing::Pairing>::ScalarField>;
//!
//! let mut rng = ark_std::test_rng();
//! let n = 8; // number of parties (must be power of 2)
//! let t = 3; // threshold
//!
//! // Setup
//! let tau = <E as ark_ec::pairing::Pairing>::ScalarField::rand(&mut rng);
//! let params = KZG10::<E, UniPoly>::setup(n, tau.clone()).unwrap();
//! let lagrange_params = LagrangePowers::<E>::new(tau, n).unwrap();
//!
//! // Key generation
//! let mut sk = vec![];
//! let mut pk = vec![];
//! for i in 0..n {
//!     let secret = SecretKey::<E>::new(&mut rng);
//!     sk.push(secret);
//!     pk.push(sk[i].lagrange_get_pk(i, &lagrange_params, n).unwrap());
//! }
//! let agg_key = AggregateKey::<E>::new(pk, &params).unwrap();
//!
//! // Encryption
//! let ct = encrypt::<E, _>(&agg_key, t, &params, &mut rng).unwrap();
//!
//! // Decryption (with t+1 parties)
//! let mut partial_decryptions = vec![<E as ark_ec::pairing::Pairing>::G2::zero(); n];
//! let mut selector = vec![false; n];
//! for i in 0..=t {
//!     selector[i] = true;
//!     partial_decryptions[i] = sk[i].partial_decryption(&ct);
//! }
//! let dec_key = agg_dec(&partial_decryptions, &ct, &selector, &agg_key, &params).unwrap();
//! ```

pub mod decryption;
pub mod encryption;
pub mod error;
pub mod kzg;
#[cfg(feature = "distributed")]
pub mod p2p;
pub mod security;
pub mod setup;
pub mod trusted_setup;
pub mod utils;

pub use error::SteError;
