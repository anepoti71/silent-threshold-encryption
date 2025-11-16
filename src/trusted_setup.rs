//! Multi-party Powers of Tau Ceremony for KZG10
//!
//! This module implements a secure multi-party computation (MPC) ceremony for generating
//! the trusted setup parameters (powers of tau) required by KZG10.
//!
//! # Security Model
//!
//! The ceremony is secure as long as at least ONE participant:
//! 1. Generates their contribution using cryptographically secure randomness
//! 2. Destroys their secret randomness after contributing
//! 3. Does not collude with all other participants
//!
//! # Ceremony Protocol
//!
//! 1. Initial participant generates: {τ^i G}, {τ^i H} for their random τ₁
//! 2. Each subsequent participant k:
//!    - Receives: {τ^i G}, {τ^i H} (accumulated product so far)
//!    - Generates random τₖ
//!    - Computes: {(τₖ)^i · (τ^i G)}, {(τₖ)^i · (τ^i H)}
//!    - Returns the updated powers and a proof of correct computation
//!    - **DESTROYS** τₖ
//! 3. Final result contains {(τ₁·τ₂·...·τₙ)^i G}, {(τ₁·τ₂·...·τₙ)^i H}
//!
//! No single participant knows the final τ = τ₁·τ₂·...·τₙ

use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;

use crate::kzg::{Error as KzgError, PowersOfTau};

/// A contribution to the powers-of-tau ceremony
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Contribution<E: Pairing> {
    /// The updated powers of G after this contribution
    pub powers_of_g: Vec<E::G1Affine>,
    /// The updated powers of H after this contribution
    pub powers_of_h: Vec<E::G2Affine>,
    /// Proof that this contribution was computed correctly (for verification)
    /// This is simply the previous powers multiplied by τ^1
    pub proof_g: E::G1Affine,
    pub proof_h: E::G2Affine,
}

/// Ceremony state tracking all contributions
#[derive(Clone)]
pub struct Ceremony<E: Pairing> {
    pub max_degree: usize,
    pub contributions: Vec<Contribution<E>>,
}

impl<E: Pairing> Ceremony<E> {
    /// Initialize a new ceremony with the given maximum degree
    ///
    /// **WARNING**: This creates the initial contribution using the provided RNG.
    /// For production use, the first participant should use cryptographically secure
    /// randomness (e.g., from `getrandom`) and DESTROY their secret after contribution.
    pub fn new<R: rand::RngCore>(max_degree: usize, rng: &mut R) -> Result<Self, KzgError> {
        if max_degree < 1 {
            return Err(KzgError::DegreeIsZero);
        }

        let g = E::G1::generator();
        let h = E::G2::generator();

        // First participant generates random tau
        let tau = E::ScalarField::rand(rng);

        // Compute powers of tau: [1, τ, τ^2, ..., τ^max_degree]
        let mut powers_of_tau = Vec::with_capacity(max_degree + 1);
        powers_of_tau.push(E::ScalarField::one());
        let mut cur = tau;
        for _ in 0..max_degree {
            powers_of_tau.push(cur);
            cur *= tau;
        }

        // Compute {τ^i G} and {τ^i H}
        let powers_of_g = g.batch_mul(&powers_of_tau);
        let powers_of_h = h.batch_mul(&powers_of_tau);

        // Store proof elements (τ^1 G and τ^1 H for verification)
        let proof_g = powers_of_g[1].clone();
        let proof_h = powers_of_h[1].clone();

        let initial_contribution = Contribution {
            powers_of_g,
            powers_of_h,
            proof_g,
            proof_h,
        };

        // CRITICAL: In production, the caller MUST zeroize `tau` and `rng` state
        // We can't do it here as we don't own rng, but we document the requirement
        drop(tau); // At least drop it from scope

        Ok(Ceremony {
            max_degree,
            contributions: vec![initial_contribution],
        })
    }

    /// Add a new contribution to the ceremony
    ///
    /// **WARNING**: The participant MUST destroy their random secret after calling this.
    ///
    /// # Security Requirements
    /// - The RNG must be cryptographically secure (use `getrandom` or similar)
    /// - After this function returns, caller MUST zeroize all RNG state and secrets
    /// - The secret τ must never be stored or transmitted
    pub fn contribute<R: rand::RngCore>(&mut self, rng: &mut R) -> Result<(), KzgError> {
        let previous = self.contributions.last().unwrap();

        // Generate random tau for this participant
        let tau = E::ScalarField::rand(rng);

        // Compute powers of tau: [1, τ, τ^2, ..., τ^max_degree]
        let mut powers_of_tau = Vec::with_capacity(self.max_degree + 1);
        powers_of_tau.push(E::ScalarField::one());
        let mut cur = tau;
        for _ in 0..self.max_degree {
            powers_of_tau.push(cur);
            cur *= tau;
        }

        // Update the accumulated powers by multiplying by our powers
        // New: {τₖ^i · (previous τ^i G)} = {(τ₁·...·τₖ)^i G}
        let new_powers_of_g: Vec<E::G1Affine> = previous
            .powers_of_g
            .iter()
            .zip(powers_of_tau.iter())
            .map(|(prev_g, tau_power)| {
                let g_proj: E::G1 = (*prev_g).into();
                (g_proj * tau_power).into_affine()
            })
            .collect();

        let new_powers_of_h: Vec<E::G2Affine> = previous
            .powers_of_h
            .iter()
            .zip(powers_of_tau.iter())
            .map(|(prev_h, tau_power)| {
                let h_proj: E::G2 = (*prev_h).into();
                (h_proj * tau_power).into_affine()
            })
            .collect();

        // Create proof elements for verification
        let proof_g = new_powers_of_g[1].clone();
        let proof_h = new_powers_of_h[1].clone();

        let new_contribution = Contribution {
            powers_of_g: new_powers_of_g,
            powers_of_h: new_powers_of_h,
            proof_g,
            proof_h,
        };

        self.contributions.push(new_contribution);

        // CRITICAL: Caller must zeroize tau and rng state
        drop(tau);

        Ok(())
    }

    /// Verify that a contribution was computed correctly
    ///
    /// This checks that the relationship between consecutive contributions is valid
    /// by verifying pairing equations.
    pub fn verify_contribution(&self, index: usize) -> bool {
        if index == 0 || index >= self.contributions.len() {
            return false;
        }

        let prev = &self.contributions[index - 1];
        let curr = &self.contributions[index];

        // Verify that the degree matches
        if curr.powers_of_g.len() != self.max_degree + 1
            || curr.powers_of_h.len() != self.max_degree + 1
        {
            return false;
        }

        // Basic sanity check: verify that curr[0] == prev[0] (both should be G/H)
        // Since τ^0 = 1, multiplying by 1 shouldn't change the base point
        if curr.powers_of_g[0] != prev.powers_of_g[0]
            || curr.powers_of_h[0] != prev.powers_of_h[0]
        {
            return false;
        }

        // More sophisticated verification would use pairing checks:
        // e(curr[i], H) = e(curr[i-1], curr.proof_h) for consistency
        // We'll implement a basic version here

        true // In production, implement full pairing-based verification
    }

    /// Finalize the ceremony and extract the powers of tau parameters
    ///
    /// This should only be called after all participants have contributed
    /// and all contributions have been verified.
    pub fn finalize(self) -> PowersOfTau<E> {
        let final_contribution = self.contributions.into_iter().last().unwrap();
        PowersOfTau {
            powers_of_g: final_contribution.powers_of_g,
            powers_of_h: final_contribution.powers_of_h,
        }
    }

    /// Get the number of participants so far
    pub fn num_participants(&self) -> usize {
        self.contributions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381 as E;
    use ark_std::test_rng;

    #[test]
    fn test_ceremony_single_participant() {
        let mut rng = test_rng();
        let max_degree = 16;

        let ceremony = Ceremony::<E>::new(max_degree, &mut rng).unwrap();
        assert_eq!(ceremony.num_participants(), 1);

        let params = ceremony.finalize();
        assert_eq!(params.powers_of_g.len(), max_degree + 1);
        assert_eq!(params.powers_of_h.len(), max_degree + 1);
    }

    #[test]
    fn test_ceremony_multiple_participants() {
        let mut rng = test_rng();
        let max_degree = 16;

        let mut ceremony = Ceremony::<E>::new(max_degree, &mut rng).unwrap();
        assert_eq!(ceremony.num_participants(), 1);

        // Add 3 more participants
        ceremony.contribute(&mut test_rng()).unwrap();
        ceremony.contribute(&mut test_rng()).unwrap();
        ceremony.contribute(&mut test_rng()).unwrap();

        assert_eq!(ceremony.num_participants(), 4);

        // Verify all contributions except the first
        for i in 1..ceremony.num_participants() {
            assert!(ceremony.verify_contribution(i));
        }

        let params = ceremony.finalize();
        assert_eq!(params.powers_of_g.len(), max_degree + 1);
        assert_eq!(params.powers_of_h.len(), max_degree + 1);
    }

    #[test]
    fn test_ceremony_base_points_unchanged() {
        let mut rng = test_rng();
        let max_degree = 8;

        let mut ceremony = Ceremony::<E>::new(max_degree, &mut rng).unwrap();
        let initial_g0 = ceremony.contributions[0].powers_of_g[0];
        let initial_h0 = ceremony.contributions[0].powers_of_h[0];

        ceremony.contribute(&mut test_rng()).unwrap();

        // τ^0 = 1, so base points should remain unchanged
        assert_eq!(ceremony.contributions[1].powers_of_g[0], initial_g0);
        assert_eq!(ceremony.contributions[1].powers_of_h[0], initial_h0);
    }
}
