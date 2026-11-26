# ML-DSA-87 PQ Sign CLI

A small command-line utility to generate ML-DSA-87 keys, sign files, and verify signatures. It is an early `0.1.0` release and should be treated as experimental.

## Requirements

- Rust 1.85 or newer (edition 2024)
- Cargo

## Build and test

```sh
cargo build --release
cargo test
```

The executable is `ml-dsa-87-pq-sign` (or `target/release/ml-dsa-87-pq-sign` when built from source). Get command-specific help with:

```sh
ml-dsa-87-pq-sign --help
ml-dsa-87-pq-sign generate-keypair --help
ml-dsa-87-pq-sign sign --help
ml-dsa-87-pq-sign verify --help
```

## Usage

Generate a keypair (defaults: `secret.seed` and `public.key` in the current directory):

```sh
ml-dsa-87-pq-sign generate-keypair
```

Sign a message file using the seed and write `message.sig`:

```sh
ml-dsa-87-pq-sign sign --secret secret.seed --message message.txt
```

Choose a different signature output path with `--signature`:

```sh
ml-dsa-87-pq-sign sign --secret secret.seed --message message.txt --signature release.sig
```

Verify the signature against the public key and the exact message bytes:

```sh
ml-dsa-87-pq-sign verify --public public.key --message message.txt --signature release.sig
```

A successful check prints `Signature is valid.`; an invalid signature or mismatched message returns a non-zero exit status.

## File formats and handling

- `secret.seed`: the 32-byte ML-DSA-87 signing seed, stored as raw binary. This is sensitive key material; keep it private and make a secure backup.
- `public.key`: the encoded ML-DSA-87 public key, stored as raw binary.
- `*.sig`: the encoded ML-DSA-87 signature, stored as raw binary.
- The message is signed and verified as-is, byte for byte; the tool does not normalize text or append a newline.

Do not share the seed. Protect it with appropriate filesystem permissions and use a trusted channel to distribute the public key. Output files are written to the paths provided; do not point them at valuable existing files.

## Security status

This project is experimental. Before relying on it for important data, independently review the implementation and its cryptographic dependencies, test interoperability with another ML-DSA-87 implementation, and assess deployment-specific security requirements. This tool does not encrypt messages or authenticate public keys for you.

## License

Licensed under the GNU General Public License, version 3 or (at your option) any later version. See [LICENSE](LICENSE) and the [official license text](https://www.gnu.org/licenses/gpl-3.0.txt).
