use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use ml_dsa::{
    EncodedVerifyingKey, Generate, KeyExport, Keypair, MlDsa87, Seed, Signature, Signer,
    SigningKey, Verifier, VerifyingKey,
};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "ml-dsa-87-pq-sign", about = "Minimal ML-DSA-87 signing CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a signing seed and its corresponding public key.
    GenerateKeypair {
        #[arg(long, default_value = "secret.seed")]
        secret: PathBuf,
        #[arg(long, default_value = "public.key")]
        public: PathBuf,
    },
    /// Sign a message file.
    Sign {
        #[arg(long)]
        secret: PathBuf,
        #[arg(long)]
        message: PathBuf,
        #[arg(long, default_value = "message.sig")]
        signature: PathBuf,
    },
    /// Verify a signature against a message file.
    Verify {
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        message: PathBuf,
        #[arg(long)]
        signature: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::GenerateKeypair { secret, public } => {
            let signing_key = SigningKey::<MlDsa87>::generate();
            let verifying_key = signing_key.verifying_key();

            fs::write(&secret, signing_key.to_bytes().as_slice())
                .with_context(|| format!("writing '{}'", secret.display()))?;
            fs::write(&public, verifying_key.encode().as_slice())
                .with_context(|| format!("writing '{}'", public.display()))?;

            println!(
                "Wrote secret seed to '{}' and public key to '{}'.",
                secret.display(),
                public.display()
            );
        }

        Command::Sign {
            secret,
            message,
            signature,
        } => {
            let secret_bytes =
                fs::read(&secret).with_context(|| format!("reading '{}'", secret.display()))?;
            let seed = Seed::try_from(secret_bytes.as_slice())
                .map_err(|_| anyhow!("secret seed must be exactly 32 bytes"))?;
            let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);

            let message_bytes =
                fs::read(&message).with_context(|| format!("reading '{}'", message.display()))?;
            let sig = signing_key
                .try_sign(&message_bytes)
                .map_err(|_| anyhow!("signing failed"))?;

            fs::write(&signature, sig.encode().as_slice())
                .with_context(|| format!("writing {}", signature.display()))?;
            println!("Wrote signature to '{}'.", signature.display());
        }

        Command::Verify {
            public,
            message,
            signature,
        } => {
            let public_bytes =
                fs::read(&public).with_context(|| format!("reading '{}'", public.display()))?;
            let encoded_public = EncodedVerifyingKey::<MlDsa87>::try_from(public_bytes.as_slice())
                .map_err(|_| anyhow!("invalid ML-DSA-87 public-key length"))?;
            let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_public);

            let message_bytes =
                fs::read(&message).with_context(|| format!("reading '{}'", message.display()))?;
            let signature_bytes = fs::read(&signature)
                .with_context(|| format!("reading '{}'", signature.display()))?;
            let sig = Signature::<MlDsa87>::try_from(signature_bytes.as_slice())
                .map_err(|_| anyhow!("invalid signature encoding"))?;

            if verifying_key.verify(&message_bytes, &sig).is_ok() {
                println!("Signature is valid.");
            } else {
                bail!("signature is invalid.");
            }
        }
    }

    Ok(())
}
