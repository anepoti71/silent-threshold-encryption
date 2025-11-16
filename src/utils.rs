use ark_ff::{FftField, Field};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial,
    Radix2EvaluationDomain,
};

/// Computes the Lagrange basis polynomial L_i(x) that is 1 at omega^i and 0 elsewhere
/// on the domain {omega^i}_{i \in [n]}.
///
/// # Arguments
/// * `n` - The number of points (must be a power of 2)
/// * `i` - The index (must be < n)
///
/// # Panics
/// Panics if n is not a power of 2 or if i >= n (in debug mode)
pub fn lagrange_poly<F: FftField>(n: usize, i: usize) -> DensePolynomial<F> {
    debug_assert!(i < n);
    debug_assert!(n.is_power_of_two());
    
    let mut evals = vec![];
    for j in 0..n {
        let l_of_x: u64 = if i == j { 1 } else { 0 };
        evals.push(F::from(l_of_x));
    }

    //powers of nth root of unity
    let domain = Radix2EvaluationDomain::<F>::new(n)
        .expect("n must be a power of 2 for Radix2EvaluationDomain");
    let eval_form = Evaluations::from_vec_and_domain(evals, domain);
    //interpolated polynomial over the n points
    eval_form.interpolate()
}

/// Interpolates a polynomial when all evaluations except at points[0] are zero.
///
/// This is an optimized interpolation for sparse polynomials.
///
/// # Arguments
/// * `eval` - The evaluation value at points[0]
/// * `points` - The points where the polynomial is zero (except at points[0])
///
/// # Returns
/// A polynomial that evaluates to `eval` at points[0] and zero at all other points.
pub fn interp_mostly_zero<F: Field>(eval: F, points: &[F]) -> DensePolynomial<F> {
    if points.is_empty() {
        // threshold=n
        return DensePolynomial::from_coefficients_vec(vec![F::one()]);
    }

    let mut interp = DensePolynomial::from_coefficients_vec(vec![F::one()]);
    for &point in &points[1..] {
        interp = interp.naive_mul(&DensePolynomial::from_coefficients_vec(vec![
            -point,
            F::one(),
        ]));
    }

    let scale = interp.evaluate(&points[0]);
    interp = &interp * (eval / scale);

    interp
}
