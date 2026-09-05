// kat.rs — D1 device-KAT runner (standalone aarch64 binary, run via `adb push` + `adb shell`).
//
// Verifies ON THIS DEVICE, against known references, every bumped libcrux code path the 4 HIGH
// advisories touched — with the exact crate versions/features the production .so links:
//   • ML-KEM-768 (libcrux-ml-kem =0.0.10) — the M1 auditor-pinned vectors via the lib's mls_kat()
//     (byte-identity to the x86 host PIN in lib.rs);
//   • ChaCha20-Poly1305 (libcrux-chacha20poly1305 =0.0.9, poly1305 0.0.6 underneath) — RFC 8439
//     §2.8.2 vector (ciphertext + tag = the poly1305 path) + round-trip + the no-panic edges the
//     advisories patched (short/tampered ciphertext → typed error, never a panic);
//   • Ed25519 (libcrux-ed25519 =0.0.9) — RFC 8032 §7.1 TEST 1 + TEST 3 (secret_to_public, sign,
//     verify) + a tamper reject.
//
// Path provenance (D1 requirement): libcrux-ml-kem's `simd128` (NEON intrinsics) feature is NOT in
// this crate's feature graph (audited via `cargo tree -i libcrux-ml-kem -e features`) — the ONLY
// compiled ML-KEM implementation is the portable one, in the runner AND in the production .so, so
// there is no alternate path to "accidentally" pass on. What the on-device run actually validates
// is LLVM's aarch64 codegen (incl. NEON autovectorization of the portable code) against the x86
// host reference — historically where ML-KEM edge bugs lived (see lib.rs KAT comment).
//
// Output is line-oriented KEY=VALUE so scripts/device-kat.ps1 can parse + verdict it. Actual bytes
// are printed for every computed value, so a FAIL report carries the full diff material.

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// RFC 8439 §2.8.2 AEAD test vector.
const AEAD_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
const AEAD_NONCE: &str = "070000004041424344454647";
const AEAD_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
const AEAD_PT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const AEAD_CT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
const AEAD_TAG: &str = "1ae10b594f09e26a7e902ecbd0600691";

// RFC 8032 §7.1 Ed25519 TEST 1 (empty message) + TEST 3 (msg = af82).
const ED_T1_SK: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED_T1_PK: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const ED_T1_SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
const ED_T3_SK: &str = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
const ED_T3_PK: &str = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
const ED_T3_MSG: &str = "af82";
const ED_T3_SIG: &str = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

fn aead_vectors() -> bool {
    use libcrux_chacha20poly1305::{decrypt, encrypt, TAG_LEN};
    let key: [u8; 32] = unhex(AEAD_KEY).try_into().unwrap();
    let nonce: [u8; 12] = unhex(AEAD_NONCE).try_into().unwrap();
    let aad = unhex(AEAD_AAD);

    // RFC 8439 vector: ciphertext AND tag (the tag is the poly1305 code path).
    let mut ct = vec![0u8; AEAD_PT.len() + TAG_LEN];
    let (ctxt, tag) = match encrypt(&key, AEAD_PT, &mut ct, &aad, &nonce) {
        Ok(x) => x,
        Err(e) => { println!("AEAD_ENCRYPT_ERR={e:?}"); return false; }
    };
    let ct_ok = hex(ctxt) == AEAD_CT;
    let tag_ok = hex(tag.as_slice()) == AEAD_TAG;
    println!("AEAD_CT={}", hex(ctxt));
    println!("AEAD_TAG={}", hex(tag.as_slice()));
    println!("AEAD_CT_OK={ct_ok}");
    println!("AEAD_TAG_OK={tag_ok}");

    // round-trip decrypt of ct||tag.
    let mut pt = vec![0u8; AEAD_PT.len()];
    let rt = matches!(decrypt(&key, &mut pt, &ct, &aad, &nonce), Ok(p) if p == AEAD_PT);
    println!("AEAD_ROUNDTRIP={rt}");

    // The advisory edges (RUSTSEC poly1305/chacha panics, fixed in the locked versions): a short
    // ciphertext and a tampered tag must yield a TYPED error — reaching this line at all means no
    // panic/abort happened on the edge inputs.
    let mut sink = vec![0u8; 64];
    let short_err = decrypt(&key, &mut sink, &[0u8; 8], &aad, &nonce).is_err();
    let mut tampered = ct.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let tamper_err = decrypt(&key, &mut pt, &tampered, &aad, &nonce).is_err();
    println!("AEAD_EDGE_OK={}", short_err && tamper_err);

    ct_ok && tag_ok && rt && short_err && tamper_err
}

fn ed25519_vectors() -> bool {
    use libcrux_ed25519::{secret_to_public, sign, verify};
    let mut all = true;
    for (name, sk_h, pk_h, msg_h, sig_h) in [
        ("T1", ED_T1_SK, ED_T1_PK, "", ED_T1_SIG),
        ("T3", ED_T3_SK, ED_T3_PK, ED_T3_MSG, ED_T3_SIG),
    ] {
        let sk: [u8; 32] = unhex(sk_h).try_into().unwrap();
        let pk_ref: [u8; 32] = unhex(pk_h).try_into().unwrap();
        let msg = unhex(msg_h);
        let mut pk = [0u8; 32];
        secret_to_public(&mut pk, &sk);
        let pk_ok = pk == pk_ref;
        let sig = match sign(&msg, &sk) {
            Ok(s) => s,
            Err(e) => { println!("ED25519_{name}_SIGN_ERR={e:?}"); all = false; continue; }
        };
        let sig_ok = hex(&sig) == sig_h;
        let ver_ok = verify(&msg, &pk_ref, &sig).is_ok();
        let mut bad = sig;
        bad[0] ^= 0x01;
        let neg_ok = verify(&msg, &pk_ref, &bad).is_err();
        println!("ED25519_{name}_PK={}", hex(&pk));
        println!("ED25519_{name}_SIG={}", hex(&sig));
        println!("ED25519_{name}_PK_OK={pk_ok}");
        println!("ED25519_{name}_SIG_OK={sig_ok}");
        println!("ED25519_{name}_VERIFY_OK={ver_ok}");
        println!("ED25519_{name}_NEG_OK={neg_ok}");
        all = all && pk_ok && sig_ok && ver_ok && neg_ok;
    }
    all
}

// --- D2 phase G: on-device performance of the portable ML-KEM path -------------------------
// Median of N iterations (median, not mean: a scheduler hiccup on a phone skews the mean badly).
// Feeds the simd128/NEON decision — enabling it is a NEW codegen path and would require repeating
// the device-KAT, so the numbers must justify it.
fn bench(iters: usize) {
    use libcrux_ml_kem::mlkem768;
    use std::time::Instant;
    let seed = [7u8; 64];
    let coins = [9u8; 32];

    let mut keygen = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let kp = mlkem768::generate_key_pair(seed);
        keygen.push(t.elapsed().as_micros() as u64);
        std::hint::black_box(kp.pk());
    }
    let kp = mlkem768::generate_key_pair(seed);

    let mut encaps = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let (ct, ss) = mlkem768::encapsulate(kp.public_key(), coins);
        encaps.push(t.elapsed().as_micros() as u64);
        std::hint::black_box((ct.as_ref().len(), ss.as_ref().len()));
    }
    let (ct, _) = mlkem768::encapsulate(kp.public_key(), coins);

    let mut decaps = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let ss = mlkem768::decapsulate(kp.private_key(), &ct);
        decaps.push(t.elapsed().as_micros() as u64);
        std::hint::black_box(ss.as_ref().len());
    }

    let med = |v: &mut Vec<u64>| { v.sort_unstable(); v[v.len() / 2] };
    println!("BENCH_ITERS={iters}");
    println!("BENCH_KEYGEN_US={}", med(&mut keygen));
    println!("BENCH_ENCAPS_US={}", med(&mut encaps));
    println!("BENCH_DECAPS_US={}", med(&mut decaps));
    // A full X-Wing handshake costs keygen+encaps+decaps once each — the UX-relevant figure for
    // creating/joining a group (one KeyPackage generation + one Welcome processing).
    let mut k2 = keygen.clone(); let mut e2 = encaps.clone(); let mut d2 = decaps.clone();
    println!("BENCH_HANDSHAKE_US={}", med(&mut k2) + med(&mut e2) + med(&mut d2));
}

fn main() {
    if std::env::args().any(|a| a == "--bench") {
        let iters = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(100);
        bench(iters);
        return;
    }
    let k = kvant_mls::mls_kat();
    println!("KAT_ARCH={}", std::env::consts::ARCH);
    println!("KAT_OS={}", std::env::consts::OS);
    println!("KAT_MLKEM_PATH=portable (simd128 feature OFF in graph; sole compiled path)");
    println!("KAT_DETERMINISTIC={}", k.deterministic);
    println!("KAT_ROUNDTRIP={}", k.roundtrip);
    println!("KAT_PK_SHA256={}", k.pk_sha256);
    println!("KAT_SS_SHA256={}", k.ss_sha256);
    println!("KAT_PINNED_OK={}", k.pinned_ok);
    let mlkem_ok = k.deterministic && k.roundtrip && k.pinned_ok;
    let aead_ok = aead_vectors();
    let ed_ok = ed25519_vectors();
    println!("DEVKAT_ALL_OK={}", mlkem_ok && aead_ok && ed_ok);
    std::process::exit(if mlkem_ok && aead_ok && ed_ok { 0 } else { 1 });
}
