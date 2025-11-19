use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use ark_bls12_381::Bls12_381 as Curve;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::CanonicalSerialize;
use clap::Parser;
use ark_std::UniformRand;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use silent_threshold_encryption::kzg::{KZG10, PowersOfTau};
use silent_threshold_encryption::setup::LagrangePowers;

#[derive(Parser, Debug)]
#[command(
    about = "Generate deterministic KZG and Lagrange parameters for P2P peers",
    author,
    version
)]
struct Args {
    /// Number of parties (must be a power of two)
    #[arg(long, default_value_t = 4)]
    parties: usize,

    /// Seed for deterministic tau generation
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Output directory for parameter files
    #[arg(long, default_value = "artifacts/p2p")]
    output_dir: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if !args.parties.is_power_of_two() {
        return Err("parties must be a power of two".into());
    }

    std::fs::create_dir_all(&args.output_dir)?;
    let mut rng = StdRng::seed_from_u64(args.seed);
    let tau = <Curve as ark_ec::pairing::Pairing>::ScalarField::rand(&mut rng);

    let kzg_params: PowersOfTau<Curve> =
        KZG10::<Curve, DensePolynomial<_>>::setup(args.parties, tau.clone())?;
    let lagrange = LagrangePowers::<Curve>::new(tau, args.parties)?;

    write_object(
        &args.output_dir.join("kzg_params.bin"),
        &kzg_params,
        "KZG parameters",
    )?;
    write_object(
        &args.output_dir.join("lagrange_params.bin"),
        &lagrange,
        "Lagrange powers",
    )?;

    println!(
        "Generated parameters for {} parties in {:?}",
        args.parties, args.output_dir
    );
    Ok(())
}

fn write_object<T: CanonicalSerialize>(
    path: &PathBuf,
    value: &T,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    value.serialize_compressed(&mut buf)?;
    let mut file = File::create(path)?;
    file.write_all(&buf)?;
    println!("  • {} -> {}", label, path.display());
    Ok(())
}
