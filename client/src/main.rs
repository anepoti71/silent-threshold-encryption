use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::{end_timer, start_timer, UniformRand, Zero};
use silent_threshold_encryption::{
    decryption::agg_dec,
    encryption::{encrypt, Ciphertext},
    kzg::KZG10,
    setup::{AggregateKey, LagrangePowers, SecretKey},
};
use std::io::{self, Write};

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

fn main() {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║   Silent Threshold Encryption - Client Demo               ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    // Get parameters from user or use defaults
    let (n, t) = get_parameters();

    println!("Configuration:");
    println!("  Total parties (n): {}", n);
    println!("  Threshold (t): {}", t);
    println!();

    // Setup phase
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Phase 1: Setup");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let mut rng = ark_std::test_rng();
    
    let kzg_timer = start_timer!(|| "Setting up KZG parameters");
    let tau = Fr::rand(&mut rng);
    let kzg_params = KZG10::<E, UniPoly381>::setup(n, tau.clone())
        .expect("Failed to setup KZG parameters");
    end_timer!(kzg_timer);
    println!("✓ KZG parameters generated");

    let lagrange_params_timer = start_timer!(|| "Preprocessing Lagrange powers");
    let lagrange_params = LagrangePowers::<E>::new(tau, n).unwrap();
    end_timer!(lagrange_params_timer);
    println!("✓ Lagrange powers preprocessed");
    println!();

    // Key generation phase
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Phase 2: Key Generation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    println!("Generating key pairs for {} parties...", n);
    let key_timer = start_timer!(|| "Key generation");
    
    // Create the dummy party's keys (party 0, always participates)
    let mut sk = Vec::with_capacity(n);
    let mut pk = Vec::with_capacity(n);
    
    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify(); // Dummy party has nullified key
    pk.push(sk[0].lagrange_get_pk(0, &lagrange_params, n).unwrap());
    
    // Generate keys for remaining parties
    for i in 1..n {
        sk.push(SecretKey::<E>::new(&mut rng));
        pk.push(sk[i].lagrange_get_pk(i, &lagrange_params, n).unwrap());
    }
    
    end_timer!(key_timer);
    println!("✓ Generated {} key pairs", n);
    println!();

    // Aggregate key generation
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Phase 3: Aggregate Key Computation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let agg_key_timer = start_timer!(|| "Computing aggregate key");
    let agg_key = AggregateKey::<E>::new(pk.clone(), &kzg_params).unwrap();
    end_timer!(agg_key_timer);
    println!("✓ Aggregate key computed");
    println!("  Aggregate key contains {} public keys", agg_key.pk.len());
    println!();

    // Encryption phase
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Phase 4: Encryption");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let enc_timer = start_timer!(|| "Encrypting");
    let ct = encrypt::<E, _>(&agg_key, t, &kzg_params, &mut rng).unwrap();
    end_timer!(enc_timer);
    println!("✓ Ciphertext generated");
    display_ciphertext_info(&ct);
    println!();

    // Decryption phase
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Phase 5: Decryption");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // Select parties for decryption (must be at least t+1 including dummy party)
    let participating_parties = select_parties(n, t);
    println!("Selected {} parties for partial decryption:", participating_parties.len());
    for &party_id in &participating_parties {
        if party_id == 0 {
            println!("  Party {} (dummy - always participates)", party_id);
        } else {
            println!("  Party {}", party_id);
        }
    }
    println!();

    // Compute partial decryptions
    println!("Computing partial decryptions...");
    let mut selector = vec![false; n];
    let mut partial_decryptions = vec![G2::zero(); n];
    
    // Dummy party always participates
    selector[0] = true;
    partial_decryptions[0] = sk[0].partial_decryption(&ct);
    
    for &party_id in &participating_parties {
        if party_id > 0 {
            selector[party_id] = true;
            partial_decryptions[party_id] = sk[party_id].partial_decryption(&ct);
        }
    }
    println!("✓ Computed {} partial decryptions", participating_parties.len());
    println!();

    // Aggregate decryption
    println!("Aggregating partial decryptions...");
    let dec_timer = start_timer!(|| "Aggregating and decrypting");
    let dec_key = agg_dec(
        &partial_decryptions,
        &ct,
        &selector,
        &agg_key,
        &kzg_params,
    ).unwrap();
    end_timer!(dec_timer);
    
    println!("✓ Decryption complete");
    println!();

    // Verify correctness
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Verification");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    if dec_key == ct.enc_key {
        println!("✓ SUCCESS: Decrypted key matches encrypted key!");
        println!("  The threshold decryption scheme is working correctly.");
    } else {
        println!("✗ ERROR: Decrypted key does not match encrypted key!");
        println!("  This indicates a problem with the implementation.");
        std::process::exit(1);
    }
    
    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║   Demo completed successfully!                             ║");
    println!("╚════════════════════════════════════════════════════════════╝");
}

fn get_parameters() -> (usize, usize) {
    print!("Enter number of parties (n) [default: 16]: ");
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let n: usize = input.trim().parse().unwrap_or(16);
    
    // Ensure n is a power of 2
    let n = if n.is_power_of_two() {
        n
    } else {
        let n_pow2 = n.next_power_of_two();
        println!("  Adjusted n to next power of 2: {}", n_pow2);
        n_pow2
    };
    
    print!("Enter threshold (t) [default: {}]: ", n / 2);
    io::stdout().flush().unwrap();
    
    input.clear();
    io::stdin().read_line(&mut input).unwrap();
    let mut t: usize = input.trim().parse().unwrap_or(n / 2);
    
    // Validate threshold
    if t >= n {
        println!("  Warning: threshold >= n, setting t = {}", n - 1);
        t = n - 1;
    }
    if t == 0 {
        println!("  Warning: threshold = 0, setting t = 1");
        t = 1;
    }
    
    (n, t)
}

fn select_parties(n: usize, t: usize) -> Vec<usize> {
    use rand::seq::IteratorRandom;
    
    let mut rng = rand::rng();
    
    // Dummy party (0) always participates, so we need t more parties
    // We need at least t+1 parties total (including dummy) for threshold t
    let num_additional = if t == 0 { 1 } else { t };
    
    // Select random parties from 1..n
    let mut selected: Vec<usize> = (1..n)
        .choose_multiple(&mut rng, num_additional.min(n - 1));
    
    // Always include dummy party (party 0)
    selected.push(0);
    selected.sort();
    selected.dedup();
    
    selected
}

fn display_ciphertext_info<E: Pairing>(ct: &Ciphertext<E>) {
    use ark_serialize::CanonicalSerialize;
    
    // Serialize ciphertext to get size
    let mut bytes = Vec::new();
    if ct.serialize_compressed(&mut bytes).is_ok() {
        println!("  Ciphertext size: {} bytes", bytes.len());
    }
    
    println!("  Threshold: {}", ct.t);
    println!("  Components:");
    println!("    - gamma_g2: G2 element");
    println!("    - sa1: 2 x G1 elements");
    println!("    - sa2: 6 x G2 elements");
    println!("    - enc_key: GT (pairing output) element");
}

