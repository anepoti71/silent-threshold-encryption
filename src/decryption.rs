use ark_ec::{
    pairing::{Pairing, PairingOutput},
    VariableBaseMSM,
};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Polynomial,
    Radix2EvaluationDomain,
};
use ark_std::{One, Zero};
use std::ops::Div;

use crate::error::SteError;
use crate::{
    encryption::Ciphertext,
    kzg::{PowersOfTau, KZG10},
    setup::AggregateKey,
    utils::interp_mostly_zero,
};

/// Helper function to compute MSM over G1 group elements.
///
/// # Errors
/// Returns an error if MSM computation fails
fn compute_msm_g1<E: Pairing>(
    bases: &[E::G1Affine],
    scalars: &[E::ScalarField],
    operation_name: &str,
) -> Result<E::G1, SteError> {
    E::G1::msm(bases, scalars)
        .map_err(|e| SteError::MsmError(format!("MSM failed in {}: {:?}", operation_name, e)))
}

/// Helper function to compute MSM over G2 group elements.
///
/// # Errors
/// Returns an error if MSM computation fails
fn compute_msm_g2<E: Pairing>(
    bases: &[E::G2Affine],
    scalars: &[E::ScalarField],
    operation_name: &str,
) -> Result<E::G2, SteError> {
    E::G2::msm(bases, scalars)
        .map_err(|e| SteError::MsmError(format!("MSM failed in {}: {:?}", operation_name, e)))
}

/// Aggregates partial decryptions and recovers the encrypted key.
///
/// # Arguments
/// * `partial_decryptions` - Partial decryptions from each party (use zero if party didn't respond)
/// * `ct` - The ciphertext to decrypt
/// * `selector` - Boolean array indicating which parties participated (true = participated)
/// * `agg_key` - The aggregate public key
/// * `params` - The KZG parameters
///
/// # Errors
/// Returns an error if inputs are invalid, lengths don't match, or operations fail
pub fn agg_dec<E: Pairing>(
    partial_decryptions: &[E::G2],
    ct: &Ciphertext<E>,
    selector: &[bool],
    agg_key: &AggregateKey<E>,
    params: &PowersOfTau<E>,
) -> Result<PairingOutput<E>, SteError> {
    let n = agg_key.pk.len();
    let t = ct.t;

    // Validate inputs
    if partial_decryptions.len() != n {
        return Err(SteError::ValidationError(format!(
            "partial_decryptions length ({}) must equal n ({})",
            partial_decryptions.len(),
            n
        )));
    }
    if selector.len() != n {
        return Err(SteError::ValidationError(format!(
            "selector length ({}) must equal n ({})",
            selector.len(),
            n
        )));
    }
    if !n.is_power_of_two() {
        return Err(SteError::InvalidParameter(format!(
            "n must be a power of 2, got {}",
            n
        )));
    }

    // Validate selector: count selected parties
    let num_selected = selector.iter().filter(|&&selected| selected).count();

    // Party 0 (dummy party) must always be selected
    if !selector.first().copied().unwrap_or(false) {
        return Err(SteError::ValidationError(
            "Party 0 (dummy party) must always be selected".to_string(),
        ));
    }

    // Must have at least t+1 parties selected (including dummy party) for threshold t
    if num_selected < t + 1 {
        return Err(SteError::InvalidThreshold(
            format!(
                "Insufficient parties selected: need at least {} parties (threshold t={}), but only {} selected",
                t + 1, t, num_selected
            )
        ));
    }

    // Cannot have more than n parties selected
    if num_selected > n {
        return Err(SteError::ValidationError(format!(
            "Too many parties selected: {} selected, but only {} parties exist",
            num_selected, n
        )));
    }

    let domain = Radix2EvaluationDomain::<E::ScalarField>::new(n).ok_or_else(|| {
        SteError::DomainError(format!(
            "Failed to create domain for n = {} (must be a power of 2)",
            n
        ))
    })?;
    let domain_elements: Vec<E::ScalarField> = domain.elements().collect();

    // points is where B is set to zero
    // parties is the set of parties who have signed
    let mut points = vec![domain_elements[0]]; // 0 is the dummy party that is always true
    let mut parties: Vec<usize> = Vec::new(); // parties indexed from 0..n-1
    for i in 0..n {
        if selector[i] {
            parties.push(i);
        } else {
            points.push(domain_elements[i]);
        }
    }

    let b = interp_mostly_zero(E::ScalarField::one(), &points);
    let b_evals = domain.fft(&b.coeffs);

    // Validate polynomial properties
    if b.degree() != points.len() - 1 {
        return Err(SteError::ValidationError(format!(
            "b.degree() ({}) != points.len() - 1 ({})",
            b.degree(),
            points.len() - 1
        )));
    }
    if b.evaluate(&domain_elements[0]) != E::ScalarField::one() {
        return Err(SteError::ValidationError(
            "b(omega^0) != 1, polynomial construction failed".to_string(),
        ));
    }

    // commit to b in g2
    let b_g2: E::G2 = KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g2(params, &b)?.into();

    // q0 = (b-1)/(x-domain_elements[0])
    let mut bminus1 = b.clone();
    bminus1.coeffs[0] -= E::ScalarField::one();

    if bminus1.evaluate(&domain_elements[0]) != E::ScalarField::zero() {
        return Err(SteError::ValidationError(
            "bminus1(omega^0) != 0, polynomial construction failed".to_string(),
        ));
    }

    let xminus1 =
        DensePolynomial::from_coefficients_vec(vec![-domain_elements[0], E::ScalarField::one()]);
    let q0 = bminus1.div(&xminus1);

    let q0_g1: E::G1 = KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, &q0)?.into();

    // bhat = x^{t+1} * b
    // insert t+1 0s at the beginning of bhat.coeffs
    let mut bhat_coeffs = vec![E::ScalarField::zero(); ct.t + 1];
    bhat_coeffs.append(&mut b.coeffs.clone());
    let bhat = DensePolynomial::from_coefficients_vec(bhat_coeffs);

    if bhat.degree() != n {
        return Err(SteError::ValidationError(format!(
            "bhat.degree() ({}) != n ({})",
            bhat.degree(),
            n
        )));
    }

    let bhat_g1: E::G1 =
        KZG10::<E, DensePolynomial<E::ScalarField>>::commit_g1(params, &bhat)?.into();

    // Convert n to field element using u64 for better precision with large values
    let n_inv = E::ScalarField::one() / E::ScalarField::from(n as u64);

    // compute the aggregate public key
    let mut bases: Vec<<E as Pairing>::G1Affine> = Vec::with_capacity(parties.len());
    let mut scalars: Vec<<E as Pairing>::ScalarField> = Vec::with_capacity(parties.len());
    for &i in &parties {
        bases.push(agg_key.pk[i].bls_pk.into());
        scalars.push(b_evals[i]);
    }
    let mut apk = compute_msm_g1::<E>(bases.as_slice(), scalars.as_slice(), "apk computation")?;
    apk *= n_inv;

    // compute sigma = (\sum B(omega^i)partial_decryptions[i])/(n) for i in parties
    bases.clear();
    scalars.clear();
    let mut bases_g2: Vec<<E as Pairing>::G2Affine> = Vec::with_capacity(parties.len());
    let mut scalars_g2: Vec<<E as Pairing>::ScalarField> = Vec::with_capacity(parties.len());
    for &i in &parties {
        bases_g2.push(partial_decryptions[i].into());
        scalars_g2.push(b_evals[i]);
    }
    let mut sigma = compute_msm_g2::<E>(
        bases_g2.as_slice(),
        scalars_g2.as_slice(),
        "sigma computation",
    )?;
    sigma *= n_inv;

    // compute Qx, Qhatx and Qz
    bases.clear();
    scalars.clear();
    for &i in &parties {
        bases.push(agg_key.pk[i].sk_li_x.into());
        scalars.push(b_evals[i]);
    }
    let qx = compute_msm_g1::<E>(bases.as_slice(), scalars.as_slice(), "qx computation")?;

    bases.clear();
    scalars.clear();
    for &i in &parties {
        bases.push(agg_key.agg_sk_li_lj_z[i].into());
        scalars.push(b_evals[i]);
    }
    let qz = compute_msm_g1::<E>(bases.as_slice(), scalars.as_slice(), "qz computation")?;

    bases.clear();
    scalars.clear();
    for &i in &parties {
        bases.push(agg_key.pk[i].sk_li_minus0.into());
        scalars.push(b_evals[i]);
    }
    let qhatx = compute_msm_g1::<E>(bases.as_slice(), scalars.as_slice(), "qhatx computation")?;

    // e(w1||sa1, sa2||w2)
    let minus1 = -E::ScalarField::one();
    let w1 = [
        apk * (minus1),
        qz * (minus1),
        qx * (minus1),
        qhatx,
        bhat_g1 * (minus1),
        q0_g1 * (minus1),
    ];
    let w2 = [b_g2, sigma];

    let mut enc_key_lhs = w1.to_vec();
    enc_key_lhs.append(&mut ct.sa1.to_vec());

    let mut enc_key_rhs = ct.sa2.to_vec();
    enc_key_rhs.append(&mut w2.to_vec());

    let enc_key = E::multi_pairing(enc_key_lhs, enc_key_rhs);

    if enc_key != ct.enc_key {
        return Err(SteError::ValidationError(
            "Decrypted key does not match encrypted key. Decryption verification failed."
                .to_string(),
        ));
    }

    Ok(enc_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encryption::encrypt,
        kzg::KZG10,
        setup::{PublicKey, SecretKey},
    };
    use ark_poly::univariate::DensePolynomial;
    use ark_std::UniformRand;

    type E = ark_bls12_381::Bls12_381;
    type G2 = <E as Pairing>::G2;
    type Fr = <E as Pairing>::ScalarField;
    type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

    #[test]
    fn test_decryption() {
        let mut rng = ark_std::test_rng();
        let n = 1 << 4; // actually n-1 total parties. one party is a dummy party that is always true
        let t: usize = n / 2;
        debug_assert!(t < n);

        let tau = Fr::rand(&mut rng);
        let params = KZG10::<E, UniPoly381>::setup(n, tau).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        // create the dummy party's keys
        sk.push(SecretKey::<E>::new(&mut rng));
        sk[0].nullify();
        pk.push(sk[0].get_pk(0, &params, n).unwrap());

        for i in 1..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(i, &params, n).unwrap())
        }

        let agg_key = AggregateKey::<E>::new(pk, &params).unwrap();
        let ct = encrypt::<E, _>(&agg_key, t, &params, &mut rng).unwrap();

        // compute partial decryptions
        let mut partial_decryptions: Vec<G2> = Vec::new();
        for sk_i in sk.iter().take(t + 1) {
            partial_decryptions.push(sk_i.partial_decryption(&ct));
        }
        for _ in t + 1..n {
            partial_decryptions.push(G2::zero());
        }

        // compute the decryption key
        let mut selector: Vec<bool> = Vec::new();
        selector.extend(std::iter::repeat_n(true, t + 1));
        selector.extend(std::iter::repeat_n(false, n - t - 1));

        let _dec_key = agg_dec(&partial_decryptions, &ct, &selector, &agg_key, &params).unwrap();
    }
}
