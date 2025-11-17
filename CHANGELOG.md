# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive module-level documentation with usage examples in `src/lib.rs`
- Detailed struct documentation explaining scheme components
- Input validation for edge cases (n == 0, t == 0) in encryption and setup
- Selector validation in `agg_dec` function:
  - Validates party 0 (dummy party) must always be selected
  - Validates at least t+1 parties are selected for threshold t
  - Validates no more than n parties are selected
- Constants for magic numbers:
  - `SA1_SIZE = 2` - Number of G1 elements in sa1 proof array
  - `SA2_SIZE = 6` - Number of G2 elements in sa2 proof array
  - `ENCRYPTION_RANDOMNESS_SIZE = 5` - Number of random scalar values used during encryption
- Helper functions in `decryption.rs`:
  - `compute_msm_g1()` - Helper for MSM over G1 group elements
  - `compute_msm_g2()` - Helper for MSM over G2 group elements
- Secure RNG implementation in client:
  - `SecureRng` wrapper using OS-backed entropy
  - Replaces deterministic `test_rng()` with cryptographically secure randomness
- Error handling improvements in client:
  - `handle_error()` function for graceful error reporting
  - `read_line()` and `prompt_and_read()` helpers for I/O error handling
  - All panics replaced with proper error handling

### Changed
- Improved type conversion in `decryption.rs`: Changed `n_inv` calculation from `u32` to `u64` for better precision with large values
- Optimized MSM operations in `decryption.rs`:
  - Reduced code duplication by extracting helper functions
  - Reused vector buffers with `Vec::with_capacity()` and `.clear()` to reduce allocations
- Changed `interp_mostly_zero()` parameter from `&Vec<F>` to `&[F]` for better ergonomics
- Error messages improved with more descriptive details
- Client now uses cryptographically secure RNG throughout (no more deterministic test RNG)

### Fixed
- Fixed incorrect party ID usage in `encryption.rs` test (was using ID 0 for all parties instead of `i`)
- Fixed missing error handling in examples:
  - Added `.unwrap()` calls for `LagrangePowers::new()`
  - Added `.unwrap()` calls for `lagrange_get_pk()`
  - Added `.unwrap()` calls for `AggregateKey::new()`
  - Added missing RNG parameter to `encrypt()` function
  - Added `.unwrap()` call for `agg_dec()`
- Fixed redundant error check in `LagrangePowers::new()`:
  - Replaced redundant `ok_or_else` check with `.expect()` since `tau` is already validated to be non-zero
- Fixed all panic points in client code with proper error handling

### Removed
- Removed unused `skip_leading_zeros_and_convert_to_bigints` function from `kzg.rs`

### Security
- Replaced deterministic `test_rng()` with cryptographically secure OS-backed RNG in client
- All cryptographic operations now use secure randomness from OS entropy
- Improved input validation to prevent invalid operations

## [0.1.0] - Original Release

Initial implementation of the silent threshold encryption scheme from [ePrint:2024/263](https://eprint.iacr.org/2024/263).

### Features
- KZG parameter setup
- Key generation (secret and public keys)
- Preprocessing of Lagrange polynomial evaluations
- Threshold encryption
- Threshold decryption with partial decryption aggregation
- BLS12-381 pairing-based implementation
- Benchmark suite for performance evaluation
- Example end-to-end usage

---

**Note:** This is a fork of the original repository with improvements and bug fixes.
