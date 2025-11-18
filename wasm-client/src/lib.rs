//! WebAssembly client for Silent Threshold Encryption
//!
//! This module provides JavaScript bindings for the silent threshold encryption scheme,
//! allowing browser-based clients to participate in distributed threshold encryption.

mod distributed_party;
pub use distributed_party::*;

use wasm_bindgen::prelude::*;
use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{rand::RngCore, UniformRand};
use silent_threshold_encryption::{
    setup::{SecretKey, PublicKey, LagrangePowers, AggregateKey},
    encryption::{encrypt, Ciphertext},
    decryption::agg_dec,
    kzg::{KZG10, PowersOfTau},
    trusted_setup::Ceremony,
};
use serde::{Serialize, Deserialize};

type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<Fr>;

/// Initialize panic hook for better error messages in the browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Log a message to the browser console
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// Macro for console logging
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

/// WebAssembly-friendly RNG using browser's crypto.getRandomValues
pub(crate) struct WasmRng;

impl RngCore for WasmRng {
    fn next_u32(&mut self) -> u32 {
        getrandom::u32().expect("Failed to get random u32")
    }

    fn next_u64(&mut self) -> u64 {
        getrandom::u64().expect("Failed to get random u64")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("Failed to get random bytes");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        match getrandom::fill(dest) {
            Ok(()) => Ok(()),
            Err(_) => Err(ark_std::rand::Error::from(
                core::num::NonZero::new(1u32).unwrap()
            )),
        }
    }
}

/// Serializable wrapper for PowersOfTau
#[derive(Serialize, Deserialize)]
pub struct SerializablePowersOfTau {
    powers_of_g: Vec<u8>,
    powers_of_h: Vec<u8>,
}

/// Serializable wrapper for LagrangePowers
#[derive(Serialize, Deserialize)]
pub struct SerializableLagrangePowers {
    data: Vec<u8>,
}

/// Serializable wrapper for PublicKey
#[derive(Serialize, Deserialize)]
pub struct SerializablePublicKey {
    data: Vec<u8>,
}

/// Serializable wrapper for Ciphertext
#[derive(Serialize, Deserialize)]
pub struct SerializableCiphertext {
    data: Vec<u8>,
}

/// Party information for distributed protocol
#[wasm_bindgen]
#[derive(Clone)]
pub struct Party {
    id: usize,
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

#[wasm_bindgen]
impl Party {
    /// Create a new party with a random secret key
    #[wasm_bindgen(constructor)]
    pub fn new(id: usize) -> Result<Party, JsValue> {
        let mut rng = WasmRng;
        let mut sk = SecretKey::<E>::new(&mut rng);

        // Nullify party 0 (dummy party)
        if id == 0 {
            sk.nullify();
        }

        let mut sk_bytes = Vec::new();
        sk.serialize_compressed(&mut sk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize secret key: {:?}", e)))?;

        Ok(Party {
            id,
            secret_key: sk_bytes,
            public_key: Vec::new(), // Will be computed later
        })
    }

    /// Get party ID
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Generate public key using preprocessed Lagrange powers
    #[wasm_bindgen(js_name = generatePublicKey)]
    pub fn generate_public_key(&mut self, lagrange_powers_bytes: &[u8], n: usize) -> Result<Vec<u8>, JsValue> {
        let sk = SecretKey::<E>::deserialize_compressed(&*self.secret_key)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize secret key: {:?}", e)))?;

        let lagrange_powers = LagrangePowers::<E>::deserialize_compressed(lagrange_powers_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize Lagrange powers: {:?}", e)))?;

        let pk = sk.lagrange_get_pk(self.id, &lagrange_powers, n)
            .map_err(|e| JsValue::from_str(&format!("Failed to generate public key: {:?}", e)))?;

        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize public key: {:?}", e)))?;

        self.public_key = pk_bytes.clone();
        Ok(pk_bytes)
    }

    /// Compute partial decryption for a ciphertext
    #[wasm_bindgen(js_name = partialDecrypt)]
    pub fn partial_decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        let sk = SecretKey::<E>::deserialize_compressed(&*self.secret_key)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize secret key: {:?}", e)))?;

        let ct = Ciphertext::<E>::deserialize_compressed(ciphertext_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ciphertext: {:?}", e)))?;

        let partial_dec = sk.partial_decryption(&ct);

        let mut partial_dec_bytes = Vec::new();
        partial_dec.serialize_compressed(&mut partial_dec_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize partial decryption: {:?}", e)))?;

        Ok(partial_dec_bytes)
    }

    /// Export secret key (for backup/recovery - use with caution!)
    #[wasm_bindgen(js_name = exportSecretKey)]
    pub fn export_secret_key(&self) -> Vec<u8> {
        self.secret_key.clone()
    }

    /// Export public key
    #[wasm_bindgen(js_name = exportPublicKey)]
    pub fn export_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}

/// Setup coordinator for the distributed protocol
#[wasm_bindgen]
pub struct Coordinator {
    n: usize,
    tau: Vec<u8>,
    kzg_params: Vec<u8>,
    lagrange_params: Vec<u8>,
}

#[wasm_bindgen]
impl Coordinator {
    /// Initialize a new coordinator with trusted setup
    ///
    /// **WARNING**: This uses a single-party trusted setup. For production,
    /// use a multi-party ceremony via the `trusted_setup` module.
    #[wasm_bindgen(constructor)]
    pub fn new(n: usize) -> Result<Coordinator, JsValue> {
        console_log!("Initializing coordinator for {} parties", n);

        if !n.is_power_of_two() {
            return Err(JsValue::from_str("n must be a power of 2"));
        }

        let mut rng = WasmRng;

        // Generate tau (WARNING: single-party setup - insecure for production)
        let tau = Fr::rand(&mut rng);

        console_log!("Setting up KZG parameters...");
        let kzg_params = KZG10::<E, UniPoly381>::setup(n, tau.clone())
            .map_err(|e| JsValue::from_str(&format!("Failed to setup KZG: {:?}", e)))?;

        console_log!("Preprocessing Lagrange powers...");
        let lagrange_params = LagrangePowers::<E>::new(tau, n)
            .map_err(|e| JsValue::from_str(&format!("Failed to create Lagrange powers: {:?}", e)))?;

        // Serialize everything
        let mut tau_bytes = Vec::new();
        tau.serialize_compressed(&mut tau_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize tau: {:?}", e)))?;

        let mut kzg_bytes = Vec::new();
        kzg_params.serialize_compressed(&mut kzg_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize KZG params: {:?}", e)))?;

        let mut lagrange_bytes = Vec::new();
        lagrange_params.serialize_compressed(&mut lagrange_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize Lagrange params: {:?}", e)))?;

        console_log!("Coordinator initialized successfully");

        Ok(Coordinator {
            n,
            tau: tau_bytes,
            kzg_params: kzg_bytes,
            lagrange_params: lagrange_bytes,
        })
    }

    /// Get the number of parties
    #[wasm_bindgen(getter)]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Export Lagrange powers for distribution to parties
    #[wasm_bindgen(js_name = exportLagrangePowers)]
    pub fn export_lagrange_powers(&self) -> Vec<u8> {
        self.lagrange_params.clone()
    }

    /// Export KZG parameters
    #[wasm_bindgen(js_name = exportKzgParams)]
    pub fn export_kzg_params(&self) -> Vec<u8> {
        self.kzg_params.clone()
    }

    /// Create aggregate key from public keys
    /// 
    /// public_keys_bytes should be a JavaScript array of Uint8Array
    #[wasm_bindgen(js_name = createAggregateKey)]
    pub fn create_aggregate_key(&self, public_keys_bytes: &js_sys::Array) -> Result<Vec<u8>, JsValue> {
        if public_keys_bytes.length() as usize != self.n {
            return Err(JsValue::from_str(&format!(
                "Expected {} public keys, got {}",
                self.n,
                public_keys_bytes.length()
            )));
        }

        let kzg_params = PowersOfTau::<E>::deserialize_compressed(&*self.kzg_params)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize KZG params: {:?}", e)))?;

        let mut pks = Vec::new();
        for i in 0..public_keys_bytes.length() {
            let pk_js = public_keys_bytes.get(i);
            let pk_bytes: Vec<u8> = serde_wasm_bindgen::from_value(pk_js)
                .map_err(|e| JsValue::from_str(&format!("Failed to convert public key {}: {:?}", i, e)))?;
            let pk = PublicKey::<E>::deserialize_compressed(&*pk_bytes)
                .map_err(|e| JsValue::from_str(&format!("Failed to deserialize public key {}: {:?}", i, e)))?;
            pks.push(pk);
        }

        let agg_key = AggregateKey::<E>::new(pks, &kzg_params)
            .map_err(|e| JsValue::from_str(&format!("Failed to create aggregate key: {:?}", e)))?;

        let mut agg_key_bytes = Vec::new();
        agg_key.serialize_compressed(&mut agg_key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize aggregate key: {:?}", e)))?;

        Ok(agg_key_bytes)
    }

    /// Encrypt a message
    #[wasm_bindgen]
    pub fn encrypt(&self, agg_key_bytes: &[u8], threshold: usize) -> Result<Vec<u8>, JsValue> {
        let agg_key = AggregateKey::<E>::deserialize_compressed(agg_key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize aggregate key: {:?}", e)))?;

        let kzg_params = PowersOfTau::<E>::deserialize_compressed(&*self.kzg_params)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize KZG params: {:?}", e)))?;

        let mut rng = WasmRng;
        let ct = encrypt::<E, _>(&agg_key, threshold, &kzg_params, &mut rng)
            .map_err(|e| JsValue::from_str(&format!("Failed to encrypt: {:?}", e)))?;

        let mut ct_bytes = Vec::new();
        ct.serialize_compressed(&mut ct_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize ciphertext: {:?}", e)))?;

        Ok(ct_bytes)
    }

    /// Aggregate decrypt using partial decryptions
    /// 
    /// partial_decryptions_bytes should be a JavaScript array of Uint8Array
    /// selector should be a JavaScript array of booleans
    #[wasm_bindgen(js_name = aggregateDecrypt)]
    pub fn aggregate_decrypt(
        &self,
        ciphertext_bytes: &[u8],
        partial_decryptions_bytes: &js_sys::Array,
        selector: &js_sys::Array,
        agg_key_bytes: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        if partial_decryptions_bytes.length() as usize != self.n {
            return Err(JsValue::from_str(&format!(
                "Expected {} partial decryptions, got {}",
                self.n,
                partial_decryptions_bytes.length()
            )));
        }

        if selector.length() as usize != self.n {
            return Err(JsValue::from_str(&format!(
                "Expected selector of length {}, got {}",
                self.n,
                selector.length()
            )));
        }

        let ct = Ciphertext::<E>::deserialize_compressed(ciphertext_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ciphertext: {:?}", e)))?;

        let agg_key = AggregateKey::<E>::deserialize_compressed(agg_key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize aggregate key: {:?}", e)))?;

        let kzg_params = PowersOfTau::<E>::deserialize_compressed(&*self.kzg_params)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize KZG params: {:?}", e)))?;

        let mut partial_decs = Vec::new();
        for i in 0..partial_decryptions_bytes.length() {
            let pd_js = partial_decryptions_bytes.get(i);
            let pd_bytes: Vec<u8> = serde_wasm_bindgen::from_value(pd_js)
                .map_err(|e| JsValue::from_str(&format!("Failed to convert partial decryption {}: {:?}", i, e)))?;
            let pd = <E as Pairing>::G2::deserialize_compressed(&*pd_bytes)
                .map_err(|e| JsValue::from_str(&format!("Failed to deserialize partial decryption {}: {:?}", i, e)))?;
            partial_decs.push(pd);
        }

        // Convert selector from JS array to Vec<bool>
        let mut selector_vec = Vec::new();
        for i in 0..selector.length() {
            let val = selector.get(i);
            let bool_val: bool = val.as_bool().unwrap_or(false);
            selector_vec.push(bool_val);
        }

        let dec_key = agg_dec(&partial_decs, &ct, &selector_vec, &agg_key, &kzg_params)
            .map_err(|e| JsValue::from_str(&format!("Failed to aggregate decrypt: {:?}", e)))?;

        let mut dec_key_bytes = Vec::new();
        dec_key.serialize_compressed(&mut dec_key_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize decryption key: {:?}", e)))?;

        Ok(dec_key_bytes)
    }
}

/// Multi-party Powers of Tau Ceremony for trusted setup
///
/// This enables browser-based participation in a distributed trusted setup ceremony.
#[wasm_bindgen]
pub struct TrustedSetupCeremony {
    ceremony: Vec<u8>,
    max_degree: usize,
}

#[wasm_bindgen]
impl TrustedSetupCeremony {
    /// Initialize a new trusted setup ceremony
    ///
    /// This creates the initial contribution. The first participant should
    /// use this to start the ceremony.
    #[wasm_bindgen(constructor)]
    pub fn new(max_degree: usize) -> Result<TrustedSetupCeremony, JsValue> {
        console_log!("Initializing trusted setup ceremony with max_degree={}", max_degree);

        let mut rng = WasmRng;
        let ceremony = Ceremony::<E>::new(max_degree, &mut rng)
            .map_err(|e| JsValue::from_str(&format!("Failed to initialize ceremony: {:?}", e)))?;

        let mut ceremony_bytes = Vec::new();
        ceremony.serialize_compressed(&mut ceremony_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize ceremony: {:?}", e)))?;

        console_log!("✓ Ceremony initialized with {} bytes", ceremony_bytes.len());

        Ok(TrustedSetupCeremony {
            ceremony: ceremony_bytes,
            max_degree,
        })
    }

    /// Load an existing ceremony state from bytes
    ///
    /// Use this to continue a ceremony or to import ceremony state from another participant
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(ceremony_bytes: &[u8], max_degree: usize) -> Result<TrustedSetupCeremony, JsValue> {
        // Validate by deserializing
        Ceremony::<E>::deserialize_compressed(ceremony_bytes)
            .map_err(|e| JsValue::from_str(&format!("Invalid ceremony data: {:?}", e)))?;

        Ok(TrustedSetupCeremony {
            ceremony: ceremony_bytes.to_vec(),
            max_degree,
        })
    }

    /// Add a new contribution to the ceremony
    ///
    /// Each participant should call this once. After calling, the participant
    /// should destroy all local state related to their random contribution.
    #[wasm_bindgen]
    pub fn contribute(&mut self) -> Result<(), JsValue> {
        console_log!("Adding contribution to ceremony...");

        let mut ceremony = Ceremony::<E>::deserialize_compressed(&*self.ceremony)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ceremony: {:?}", e)))?;

        let participant_id = ceremony.num_participants();
        console_log!("Contributing as participant #{}", participant_id);

        let mut rng = WasmRng;
        ceremony.contribute(&mut rng)
            .map_err(|e| JsValue::from_str(&format!("Failed to contribute: {:?}", e)))?;

        // Serialize updated ceremony
        let mut ceremony_bytes = Vec::new();
        ceremony.serialize_compressed(&mut ceremony_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize ceremony: {:?}", e)))?;

        self.ceremony = ceremony_bytes;

        console_log!("✓ Contribution added successfully");
        console_log!("⚠ IMPORTANT: Participant should now destroy all local random state!");

        Ok(())
    }

    /// Verify all contributions in the ceremony
    ///
    /// Returns true if all contributions are valid
    #[wasm_bindgen(js_name = verifyAll)]
    pub fn verify_all(&self) -> Result<bool, JsValue> {
        console_log!("Verifying all contributions...");

        let ceremony = Ceremony::<E>::deserialize_compressed(&*self.ceremony)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ceremony: {:?}", e)))?;

        let num_participants = ceremony.num_participants();
        console_log!("Verifying {} contributions...", num_participants - 1);

        for i in 1..num_participants {
            if !ceremony.verify_contribution(i) {
                console_log!("✗ Contribution {} failed verification", i);
                return Ok(false);
            }
            console_log!("✓ Contribution {} verified", i);
        }

        console_log!("✓ All contributions verified successfully");
        Ok(true)
    }

    /// Get the number of participants so far
    #[wasm_bindgen(js_name = numParticipants)]
    pub fn num_participants(&self) -> Result<usize, JsValue> {
        let ceremony = Ceremony::<E>::deserialize_compressed(&*self.ceremony)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ceremony: {:?}", e)))?;

        Ok(ceremony.num_participants())
    }

    /// Finalize the ceremony and extract the KZG parameters
    ///
    /// This should only be called after all participants have contributed
    /// and all contributions have been verified.
    #[wasm_bindgen]
    pub fn finalize(&self) -> Result<Vec<u8>, JsValue> {
        console_log!("Finalizing ceremony...");

        let ceremony = Ceremony::<E>::deserialize_compressed(&*self.ceremony)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ceremony: {:?}", e)))?;

        let params = ceremony.finalize()
            .map_err(|e| JsValue::from_str(&format!("Failed to finalize ceremony: {:?}", e)))?;

        let mut params_bytes = Vec::new();
        params.serialize_compressed(&mut params_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize parameters: {:?}", e)))?;

        console_log!("✓ Ceremony finalized successfully ({} bytes)", params_bytes.len());

        Ok(params_bytes)
    }

    /// Export ceremony state for transmission to next participant
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Vec<u8> {
        self.ceremony.clone()
    }

    /// Get ceremony statistics
    #[wasm_bindgen(js_name = getStats)]
    pub fn get_stats(&self) -> Result<String, JsValue> {
        let ceremony = Ceremony::<E>::deserialize_compressed(&*self.ceremony)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ceremony: {:?}", e)))?;

        let stats = serde_json::json!({
            "max_degree": self.max_degree,
            "num_participants": ceremony.num_participants(),
            "state_size_bytes": self.ceremony.len(),
        });

        Ok(stats.to_string())
    }
}

/// Create a Coordinator from finalized trusted setup parameters
#[wasm_bindgen(js_name = coordinatorFromTrustedSetup)]
pub fn coordinator_from_trusted_setup(
    kzg_params_bytes: &[u8],
    n: usize,
) -> Result<Coordinator, JsValue> {
    console_log!("Creating coordinator from trusted setup parameters...");

    if !is_power_of_two(n) {
        return Err(JsValue::from_str("n must be a power of 2"));
    }

    let _kzg_params = PowersOfTau::<E>::deserialize_compressed(kzg_params_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize KZG params: {:?}", e)))?;

    // We still need tau to compute Lagrange powers
    // In a real setup, this would be derived from the ceremony
    // For now, we need to pass tau separately or recompute from powers
    // This is a limitation of the current API

    return Err(JsValue::from_str(
        "Creating coordinator from trusted setup requires tau. \
         Use the regular Coordinator constructor for single-party setup, \
         or implement tau extraction from powers (advanced)."
    ));
}

/// Utility functions for the WASM client
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[wasm_bindgen]
pub fn is_power_of_two(n: usize) -> bool {
    n > 0 && (n & (n - 1)) == 0
}
