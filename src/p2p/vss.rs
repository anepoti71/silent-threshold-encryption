//! Verifiable Secret Sharing (VSS) for distributed KZG parameter generation
//!
//! This module implements a simple VSS scheme that allows parties to
//! collaboratively generate the KZG parameters without any trusted party.
//!
//! Each party contributes randomness, and the final tau is the sum of all contributions.
//! Feldman VSS commitments allow verification without revealing individual secrets.

use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use std::marker::PhantomData;

/// VSS share for a party
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VSSShare<E: Pairing> {
    /// The party's share of the secret
    pub share: E::ScalarField,
    /// Polynomial commitments for verification
    pub commitments: Vec<E::G1>,
}

/// VSS dealer (party creating shares)
pub struct VSSDealer<E: Pairing> {
    /// The secret polynomial
    polynomial: DensePolynomial<E::ScalarField>,
    /// Commitments to polynomial coefficients
    commitments: Vec<E::G1>,
    _phantom: PhantomData<E>,
}

impl<E: Pairing> VSSDealer<E> {
    /// Create a new VSS dealer with a random secret
    ///
    /// # Arguments
    /// * `threshold` - The threshold value (degree of polynomial is t-1)
    /// * `generator` - The generator point for commitments
    /// * `rng` - Random number generator
    pub fn new<R: RngCore>(
        threshold: usize,
        generator: E::G1,
        rng: &mut R,
    ) -> Result<Self, String> {
        if threshold == 0 {
            return Err("Threshold must be at least 1".to_string());
        }

        // Create random polynomial of degree t-1
        let coefficients: Vec<E::ScalarField> =
            (0..threshold).map(|_| E::ScalarField::rand(rng)).collect();

        let polynomial = DensePolynomial::from_coefficients_vec(coefficients);

        // Compute commitments to each coefficient
        let commitments: Vec<E::G1> = polynomial
            .coeffs()
            .iter()
            .map(|coeff| generator * coeff)
            .collect();

        Ok(Self {
            polynomial,
            commitments,
            _phantom: PhantomData,
        })
    }

    /// Get the secret (constant term of polynomial)
    pub fn secret(&self) -> E::ScalarField {
        self.polynomial.coeffs()[0]
    }

    /// Get commitments
    pub fn commitments(&self) -> &[E::G1] {
        &self.commitments
    }

    /// Generate share for party i
    ///
    /// # Arguments
    /// * `party_id` - The party identifier (1-indexed)
    pub fn generate_share(&self, party_id: usize) -> Result<VSSShare<E>, String> {
        if party_id == 0 {
            return Err("Party ID must be >= 1".to_string());
        }

        // Evaluate polynomial at party_id
        let x = E::ScalarField::from(party_id as u64);
        let share = self.polynomial.evaluate(&x);

        Ok(VSSShare {
            share,
            commitments: self.commitments.clone(),
        })
    }

    /// Generate shares for all n parties
    pub fn generate_shares(&self, n: usize) -> Result<Vec<VSSShare<E>>, String> {
        (1..=n).map(|i| self.generate_share(i)).collect()
    }
}

/// VSS participant (party receiving and verifying shares)
pub struct VSSParticipant<E: Pairing> {
    /// Party ID
    party_id: usize,
    /// Received shares from other parties
    received_shares: Vec<(usize, VSSShare<E>)>,
    _phantom: PhantomData<E>,
}

impl<E: Pairing> VSSParticipant<E> {
    /// Create new VSS participant
    pub fn new(party_id: usize) -> Self {
        Self {
            party_id,
            received_shares: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Verify a received share
    ///
    /// Checks that the share is consistent with the commitments
    /// using Feldman VSS verification
    pub fn verify_share(&self, share: &VSSShare<E>, generator: E::G1) -> Result<bool, String> {
        if share.commitments.is_empty() {
            return Err("No commitments provided".to_string());
        }

        // Compute g^{f(i)} from commitments
        // f(i) = c_0 + c_1*i + c_2*i^2 + ... + c_{t-1}*i^{t-1}
        // g^{f(i)} = g^{c_0} * g^{c_1*i} * g^{c_2*i^2} * ...
        let x = E::ScalarField::from(self.party_id as u64);
        let mut x_power = E::ScalarField::from(1u64);

        let mut expected_commitment = share.commitments[0];
        for commitment in share.commitments.iter().skip(1) {
            x_power *= x;
            expected_commitment += *commitment * x_power;
        }

        // Compute g^{share}
        let share_commitment = generator * share.share;

        // Verify they match
        Ok(expected_commitment == share_commitment)
    }

    /// Add a verified share
    pub fn add_share(&mut self, dealer_id: usize, share: VSSShare<E>) {
        self.received_shares.push((dealer_id, share));
    }

    /// Reconstruct the secret from received shares
    ///
    /// Computes the party's share of the combined secret as the sum of all received shares
    pub fn reconstruct_share(&self) -> Result<E::ScalarField, String> {
        if self.received_shares.is_empty() {
            return Err("No shares received".to_string());
        }

        use ark_ff::Field;
        let combined_share = self
            .received_shares
            .iter()
            .map(|(_, share)| share.share)
            .reduce(|a, b| a + b)
            .unwrap();

        Ok(combined_share)
    }

    /// Get number of received shares
    pub fn share_count(&self) -> usize {
        self.received_shares.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381 as E;
    use ark_ec::Group;

    type G1 = <E as Pairing>::G1;

    #[test]
    fn test_vss_single_dealer() {
        let mut rng = ark_std::test_rng();
        let g = G1::generator();
        let n = 5;
        let t = 3;

        // Create dealer
        let dealer = VSSDealer::<E>::new(t, g, &mut rng).unwrap();
        let secret = dealer.secret();

        // Generate shares
        let shares = dealer.generate_shares(n).unwrap();
        assert_eq!(shares.len(), n);

        // Each party verifies their share
        for (i, share) in shares.iter().enumerate() {
            let party_id = i + 1;
            let participant = VSSParticipant::<E>::new(party_id);
            let valid = participant.verify_share(share, g).unwrap();
            assert!(valid, "Share {} verification failed", party_id);
        }
    }

    #[test]
    fn test_vss_multiple_dealers() {
        let mut rng = ark_std::test_rng();
        let g = G1::generator();
        let n = 4;
        let t = 2;

        // Each of n parties acts as a dealer
        let mut all_shares = vec![vec![]; n];

        for dealer_id in 0..n {
            let dealer = VSSDealer::<E>::new(t, g, &mut rng).unwrap();
            let shares = dealer.generate_shares(n).unwrap();

            // Distribute shares to participants
            for (party_id, share) in shares.into_iter().enumerate() {
                all_shares[party_id].push((dealer_id, share));
            }
        }

        // Each party verifies and combines their shares
        for party_id in 0..n {
            let mut participant = VSSParticipant::<E>::new(party_id + 1);

            for (dealer_id, share) in &all_shares[party_id] {
                let valid = participant.verify_share(share, g).unwrap();
                assert!(
                    valid,
                    "Party {} failed to verify share from dealer {}",
                    party_id, dealer_id
                );
                participant.add_share(*dealer_id, share.clone());
            }

            assert_eq!(participant.share_count(), n);

            // Reconstruct combined share
            let _combined = participant.reconstruct_share().unwrap();
        }
    }

    #[test]
    fn test_vss_invalid_threshold() {
        let mut rng = ark_std::test_rng();
        let g = G1::generator();

        let result = VSSDealer::<E>::new(0, g, &mut rng);
        assert!(result.is_err());
    }
}
