use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX epoch")
            .as_nanos();
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("ml-dsa-cli-test-{}-{nonce}-{id}", std::process::id()));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ml-dsa-87-pq-sign"))
        .args(args)
        .output()
        .expect("run CLI")
}

#[test]
fn generate_sign_and_verify_round_trip() {
    let dir = TestDir::new();
    let secret = dir.0.join("secret.seed");
    let public = dir.0.join("public.key");
    let message = dir.0.join("message.bin");
    let signature = dir.0.join("message.sig");

    let generated = Command::new(env!("CARGO_BIN_EXE_ml-dsa-87-pq-sign"))
        .args([
            "generate-keypair",
            "--secret",
            secret.to_str().unwrap(),
            "--public",
            public.to_str().unwrap(),
        ])
        .output()
        .expect("generate keypair");
    assert!(generated.status.success(), "{}", String::from_utf8_lossy(&generated.stderr));
    assert_eq!(fs::metadata(&secret).unwrap().len(), 32);
    assert!(fs::metadata(&public).unwrap().len() > 0);

    fs::write(&message, b"binary-safe message\0with bytes\n").unwrap();
    let signed = Command::new(env!("CARGO_BIN_EXE_ml-dsa-87-pq-sign"))
        .args([
            "sign",
            "--secret",
            secret.to_str().unwrap(),
            "--message",
            message.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
        ])
        .output()
        .expect("sign message");
    assert!(signed.status.success(), "{}", String::from_utf8_lossy(&signed.stderr));
    assert!(fs::metadata(&signature).unwrap().len() > 0);

    let verified = Command::new(env!("CARGO_BIN_EXE_ml-dsa-87-pq-sign"))
        .args([
            "verify",
            "--public",
            public.to_str().unwrap(),
            "--message",
            message.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
        ])
        .output()
        .expect("verify signature");
    assert!(verified.status.success(), "{}", String::from_utf8_lossy(&verified.stderr));
    assert!(String::from_utf8_lossy(&verified.stdout).contains("Signature is valid."));

    fs::write(&message, b"altered message").unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_ml-dsa-87-pq-sign"))
        .args([
            "verify",
            "--public",
            public.to_str().unwrap(),
            "--message",
            message.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
        ])
        .output()
        .expect("verify altered message");
    assert!(!rejected.status.success());
}

#[test]
fn sign_rejects_seed_with_wrong_length() {
    let dir = TestDir::new();
    let secret = dir.0.join("short.seed");
    let message = dir.0.join("message.txt");
    fs::write(&secret, b"too short").unwrap();
    fs::write(&message, b"message").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ml-dsa-87-pq-sign"))
        .args([
            "sign",
            "--secret",
            secret.to_str().unwrap(),
            "--message",
            message.to_str().unwrap(),
        ])
        .output()
        .expect("run sign command");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly 32 bytes"));
}
