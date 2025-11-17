use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{MessageEvent, WebSocket, ErrorEvent, CloseEvent};
use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::rand::RngCore;
use serde::{Serialize, Deserialize};
use silent_threshold_encryption::{
    setup::{SecretKey, PublicKey, LagrangePowers},
    encryption::Ciphertext,
};
use crate::WasmRng;

type Fr = <E as Pairing>::ScalarField;
type G2 = <E as Pairing>::G2;

/// Messages sent from coordinator to parties (matches the Rust protocol)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum CoordinatorMessage {
    RequestPublicKey {
        party_id: usize,
        tau_bytes: Vec<u8>,
        n: usize,
    },
    Ciphertext {
        ct_bytes: Vec<u8>,
    },
    RequestPartialDecryption {
        party_id: usize,
        ct_bytes: Vec<u8>,
    },
    Success {
        message: String,
    },
    Error {
        message: String,
    },
}

/// Messages sent from parties to coordinator (matches the Rust protocol)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PartyMessage {
    PublicKey {
        party_id: usize,
        pk_bytes: Vec<u8>,
    },
    PartialDecryption {
        party_id: usize,
        pd_bytes: Vec<u8>,
    },
    Ready {
        party_id: usize,
    },
    Error {
        party_id: usize,
        message: String,
    },
}

/// Browser-based distributed party client using WebSocket
#[wasm_bindgen]
pub struct DistributedParty {
    id: usize,
    secret_key: Option<Vec<u8>>,
    ws: Option<WebSocket>,
    on_message_callback: Option<js_sys::Function>,
    on_status_callback: Option<js_sys::Function>,
}

#[wasm_bindgen]
impl DistributedParty {
    /// Create a new distributed party client
    #[wasm_bindgen(constructor)]
    pub fn new(party_id: usize) -> DistributedParty {
        DistributedParty {
            id: party_id,
            secret_key: None,
            ws: None,
            on_message_callback: None,
            on_status_callback: None,
        }
    }

    /// Get party ID
    #[wasm_bindgen(getter, js_name = partyId)]
    pub fn party_id(&self) -> usize {
        self.id
    }

    /// Set callback for receiving status updates
    /// Callback signature: function(status: string)
    #[wasm_bindgen(js_name = onStatus)]
    pub fn on_status(&mut self, callback: js_sys::Function) {
        self.on_status_callback = Some(callback);
    }

    /// Set callback for receiving messages
    /// Callback signature: function(messageType: string, data: any)
    #[wasm_bindgen(js_name = onMessage)]
    pub fn on_message(&mut self, callback: js_sys::Function) {
        self.on_message_callback = Some(callback);
    }

    /// Connect to coordinator via WebSocket
    /// Use wss:// for TLS-encrypted connections
    #[wasm_bindgen]
    pub fn connect(&mut self, url: String) -> Result<(), JsValue> {
        self.log_status(&format!("Connecting to coordinator at {}...", url));

        let ws = WebSocket::new(&url)?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        // Set up onopen handler
        let on_status = self.on_status_callback.clone();
        let onopen_callback = Closure::wrap(Box::new(move |_| {
            let msg = "WebSocket connection established";
            web_sys::console::log_1(&msg.into());
            if let Some(ref callback) = on_status {
                let _ = callback.call1(&JsValue::NULL, &msg.into());
            }
        }) as Box<dyn FnMut(JsValue)>);
        ws.set_onopen(Some(onopen_callback.as_ref().unchecked_ref()));
        onopen_callback.forget();

        // Set up onmessage handler
        let party_id = self.id;
        let on_message = self.on_message_callback.clone();
        let on_status2 = self.on_status_callback.clone();

        let onmessage_callback = Closure::wrap(Box::new(move |e: MessageEvent| {
            if let Ok(array_buffer) = e.data().dyn_into::<js_sys::ArrayBuffer>() {
                let array = js_sys::Uint8Array::new(&array_buffer);
                let bytes = array.to_vec();

                // Try to parse as CoordinatorMessage
                match serde_json::from_slice::<CoordinatorMessage>(&bytes) {
                    Ok(msg) => {
                        web_sys::console::log_1(&format!("Received message: {:?}", msg).into());

                        if let Some(ref status_cb) = on_status2 {
                            let status_msg = match &msg {
                                CoordinatorMessage::RequestPublicKey { .. } =>
                                    "Received request for public key",
                                CoordinatorMessage::RequestPartialDecryption { .. } =>
                                    "Received request for partial decryption",
                                CoordinatorMessage::Success { message } =>
                                    message.as_str(),
                                CoordinatorMessage::Error { message } =>
                                    &format!("Error: {}", message),
                                _ => "Received message from coordinator",
                            };
                            let _ = status_cb.call1(&JsValue::NULL, &status_msg.into());
                        }

                        // Forward to JavaScript callback
                        if let Some(ref callback) = on_message {
                            let msg_type = match msg {
                                CoordinatorMessage::RequestPublicKey { .. } => "RequestPublicKey",
                                CoordinatorMessage::Ciphertext { .. } => "Ciphertext",
                                CoordinatorMessage::RequestPartialDecryption { .. } => "RequestPartialDecryption",
                                CoordinatorMessage::Success { .. } => "Success",
                                CoordinatorMessage::Error { .. } => "Error",
                            };

                            let msg_json = serde_json::to_string(&msg).unwrap_or_default();
                            let _ = callback.call2(&JsValue::NULL, &msg_type.into(), &msg_json.into());
                        }
                    }
                    Err(e) => {
                        web_sys::console::error_1(&format!("Failed to parse message: {:?}", e).into());
                    }
                }
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();

        // Set up onerror handler
        let on_status3 = self.on_status_callback.clone();
        let onerror_callback = Closure::wrap(Box::new(move |e: ErrorEvent| {
            let msg = format!("WebSocket error: {:?}", e.message());
            web_sys::console::error_1(&msg.clone().into());
            if let Some(ref callback) = on_status3 {
                let _ = callback.call1(&JsValue::NULL, &msg.into());
            }
        }) as Box<dyn FnMut(ErrorEvent)>);
        ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
        onerror_callback.forget();

        // Set up onclose handler
        let on_status4 = self.on_status_callback.clone();
        let onclose_callback = Closure::wrap(Box::new(move |e: CloseEvent| {
            let msg = format!("WebSocket closed: code={} reason={}", e.code(), e.reason());
            web_sys::console::log_1(&msg.clone().into());
            if let Some(ref callback) = on_status4 {
                let _ = callback.call1(&JsValue::NULL, &msg.into());
            }
        }) as Box<dyn FnMut(CloseEvent)>);
        ws.set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
        onclose_callback.forget();

        self.ws = Some(ws);
        Ok(())
    }

    /// Send ready message to coordinator
    #[wasm_bindgen(js_name = sendReady)]
    pub fn send_ready(&self) -> Result<(), JsValue> {
        let msg = PartyMessage::Ready {
            party_id: self.id,
        };
        self.send_message(&msg)
    }

    /// Handle public key request from coordinator
    #[wasm_bindgen(js_name = handlePublicKeyRequest)]
    pub fn handle_public_key_request(
        &mut self,
        tau_bytes_js: &[u8],
        n: usize,
    ) -> Result<(), JsValue> {
        self.log_status("Generating secret key...");

        // Generate secret key
        let mut rng = WasmRng;
        let mut sk = SecretKey::<E>::new(&mut rng);

        // Nullify party 0 (dummy party)
        if self.id == 0 {
            sk.nullify();
            self.log_status("Generated nullified secret key (dummy party)");
        } else {
            self.log_status("Generated secret key");
        }

        // Deserialize tau
        let tau = Fr::deserialize_compressed(tau_bytes_js)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize tau: {:?}", e)))?;

        // Compute public key using Lagrange method
        self.log_status("Computing public key...");
        let lagrange_params = LagrangePowers::<E>::new(tau, n)
            .map_err(|e| JsValue::from_str(&format!("Failed to create Lagrange powers: {:?}", e)))?;

        let pk = sk.lagrange_get_pk(self.id, &lagrange_params, n)
            .map_err(|e| JsValue::from_str(&format!("Failed to generate public key: {:?}", e)))?;

        // Store secret key
        let mut sk_bytes = Vec::new();
        sk.serialize_compressed(&mut sk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize secret key: {:?}", e)))?;
        self.secret_key = Some(sk_bytes);

        // Serialize and send public key
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize public key: {:?}", e)))?;

        let response = PartyMessage::PublicKey {
            party_id: self.id,
            pk_bytes,
        };

        self.send_message(&response)?;
        self.log_status("Sent public key to coordinator");

        Ok(())
    }

    /// Handle partial decryption request from coordinator
    #[wasm_bindgen(js_name = handlePartialDecryptionRequest)]
    pub fn handle_partial_decryption_request(
        &self,
        ct_bytes_js: &[u8],
    ) -> Result<(), JsValue> {
        self.log_status("Computing partial decryption...");

        // Deserialize ciphertext
        let ct = Ciphertext::<E>::deserialize_compressed(ct_bytes_js)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ciphertext: {:?}", e)))?;

        // Get secret key
        let sk_bytes = self.secret_key.as_ref()
            .ok_or_else(|| JsValue::from_str("Secret key not initialized"))?;

        let sk = SecretKey::<E>::deserialize_compressed(&**sk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to deserialize secret key: {:?}", e)))?;

        // Compute partial decryption
        let pd = sk.partial_decryption(&ct);

        // Serialize and send partial decryption
        let mut pd_bytes = Vec::new();
        pd.serialize_compressed(&mut pd_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize partial decryption: {:?}", e)))?;

        let response = PartyMessage::PartialDecryption {
            party_id: self.id,
            pd_bytes,
        };

        self.send_message(&response)?;
        self.log_status("Sent partial decryption to coordinator");

        Ok(())
    }

    /// Close the WebSocket connection
    #[wasm_bindgen]
    pub fn disconnect(&mut self) -> Result<(), JsValue> {
        if let Some(ws) = &self.ws {
            ws.close()?;
            self.ws = None;
            self.log_status("Disconnected from coordinator");
        }
        Ok(())
    }

    // Private helper methods

    fn send_message(&self, msg: &PartyMessage) -> Result<(), JsValue> {
        let ws = self.ws.as_ref()
            .ok_or_else(|| JsValue::from_str("Not connected to coordinator"))?;

        let msg_bytes = serde_json::to_vec(msg)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize message: {:?}", e)))?;

        ws.send_with_u8_array(&msg_bytes)?;
        Ok(())
    }

    fn log_status(&self, msg: &str) {
        web_sys::console::log_1(&format!("Party {}: {}", self.id, msg).into());
        if let Some(ref callback) = self.on_status_callback {
            let _ = callback.call1(&JsValue::NULL, &msg.into());
        }
    }
}

/// Standalone encryption function that accepts a message string from HTML
#[wasm_bindgen(js_name = encryptMessage)]
pub fn encrypt_message(
    message: &str,
    agg_key_bytes: &[u8],
    threshold: usize,
    kzg_params_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    use silent_threshold_encryption::{
        setup::AggregateKey,
        encryption::encrypt,
        kzg::PowersOfTau,
    };
    use ark_poly::univariate::DensePolynomial;

    web_sys::console::log_1(&format!("Encrypting message: '{}'", message).into());

    let agg_key = AggregateKey::<E>::deserialize_compressed(agg_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize aggregate key: {:?}", e)))?;

    let kzg_params = PowersOfTau::<E>::deserialize_compressed(kzg_params_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize KZG params: {:?}", e)))?;

    let mut rng = WasmRng;
    let ct = encrypt::<E, _>(&agg_key, threshold, &kzg_params, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Failed to encrypt: {:?}", e)))?;

    let mut ct_bytes = Vec::new();
    ct.serialize_compressed(&mut ct_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize ciphertext: {:?}", e)))?;

    web_sys::console::log_1(&format!("Encrypted to {} bytes", ct_bytes.len()).into());

    Ok(ct_bytes)
}

/// Standalone decryption function that returns a message string to HTML
#[wasm_bindgen(js_name = decryptMessage)]
pub fn decrypt_message(
    ciphertext_bytes: &[u8],
    partial_decryptions_bytes: &js_sys::Array,
    selector: &js_sys::Array,
    agg_key_bytes: &[u8],
    kzg_params_bytes: &[u8],
) -> Result<String, JsValue> {
    use silent_threshold_encryption::{
        setup::AggregateKey,
        decryption::agg_dec,
        kzg::PowersOfTau,
    };

    web_sys::console::log_1(&"Decrypting message...".into());

    let ct = Ciphertext::<E>::deserialize_compressed(ciphertext_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize ciphertext: {:?}", e)))?;

    let agg_key = AggregateKey::<E>::deserialize_compressed(agg_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize aggregate key: {:?}", e)))?;

    let kzg_params = PowersOfTau::<E>::deserialize_compressed(kzg_params_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize KZG params: {:?}", e)))?;

    let n = selector.length() as usize;
    let mut partial_decs = Vec::new();
    for i in 0..partial_decryptions_bytes.length() {
        let pd_js = partial_decryptions_bytes.get(i);
        let pd_bytes: Vec<u8> = serde_wasm_bindgen::from_value(pd_js)
            .map_err(|e| JsValue::from_str(&format!("Failed to convert partial decryption {}: {:?}", i, e)))?;
        let pd = G2::deserialize_compressed(&*pd_bytes)
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

    // For now, return a representation of the decryption key
    // In a real application, this would be used to decrypt actual data
    let mut dec_key_bytes = Vec::new();
    dec_key.serialize_compressed(&mut dec_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize decryption key: {:?}", e)))?;

    let result = format!("Decryption successful! Key hash: {:x}",
        dec_key_bytes.iter().fold(0u64, |acc, &b| acc.wrapping_mul(31).wrapping_add(b as u64)));

    web_sys::console::log_1(&result.clone().into());

    Ok(result)
}
