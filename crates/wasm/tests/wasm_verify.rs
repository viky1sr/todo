use todo_crypto::aes_gcm_siv_encrypt_sequential;
use todo_ipfs::cid::{Cid, codec};
use todo_ipfs::manifest::{BlockLink, ObjectManifest};
use todo_wasm::{
    WasmCidVerifier, encode_hex, todo_wasm_alloc, todo_wasm_decrypt_decompress, todo_wasm_free,
    todo_wasm_parse_manifest, todo_wasm_verify_block,
};
use todo_zstd::pipeline::StreamCryptoPipeline;

#[test]
fn test_cid_multihash_verification_and_tampering() {
    let raw_data = b"Encrypted chunk payload for decentralized IPFS test";
    let cid = Cid::sha2_256(codec::RAW, raw_data);
    let cid_str = cid.to_string();

    // Valid verification
    assert!(WasmCidVerifier::verify_block(raw_data, &cid_str).unwrap());

    // Tampered verification (1 bit flip)
    let mut tampered = raw_data.to_vec();
    tampered[0] ^= 0x01;
    assert!(!WasmCidVerifier::verify_block(&tampered, &cid_str).unwrap());

    // Invalid CID string
    assert!(WasmCidVerifier::verify_block(raw_data, "not-a-valid-cid").is_err());
}

#[test]
fn test_dag_json_manifest_parsing() {
    let b1_cid = Cid::sha2_256(codec::RAW, b"chunk1");
    let b2_cid = Cid::sha2_256(codec::RAW, b"chunk2");
    let manifest = ObjectManifest::new(
        "test-stream-001",
        vec![
            BlockLink {
                cid: b1_cid.clone(),
                size: 6,
            },
            BlockLink {
                cid: b2_cid.clone(),
                size: 6,
            },
        ],
    )
    .unwrap();

    let dag_json = manifest.to_dag_json();
    let parsed = WasmCidVerifier::parse_manifest(&dag_json).unwrap();

    assert_eq!(parsed.object_id, "test-stream-001");
    assert_eq!(parsed.total_size, 12);
    assert_eq!(parsed.blocks.len(), 2);
    assert_eq!(parsed.blocks[0].cid, b1_cid.to_string());
    assert_eq!(parsed.blocks[0].size, 6);
    assert_eq!(parsed.blocks[1].cid, b2_cid.to_string());
    assert_eq!(parsed.blocks[1].size, 6);
}

#[test]
fn test_client_side_aes_gcm_siv_decryption_and_decompression() {
    let key = [0x55u8; 32];
    let nonce = [0x77u8; 12];
    let key_hex = encode_hex(&key);
    let nonce_hex = encode_hex(&nonce);

    let original_payload = b"Top Secret Payload: Cryptographic Invariants Must Hold True!";

    // 1. Pipeline sealed stream format
    let pipeline = StreamCryptoPipeline::default();
    let sealed = pipeline
        .compress_and_encrypt(original_payload, &key, &nonce)
        .unwrap();
    let sealed_bytes = sealed.to_bytes();

    let recovered =
        WasmCidVerifier::decrypt_and_decompress(&sealed_bytes, &key_hex, &nonce_hex).unwrap();
    assert_eq!(recovered, original_payload);

    // Tampered sealed stream ciphertext -> must fail closed
    let mut tampered_sealed = sealed_bytes.clone();
    let last = tampered_sealed.len() - 1;
    tampered_sealed[last] ^= 0x42;
    assert!(
        WasmCidVerifier::decrypt_and_decompress(&tampered_sealed, &key_hex, &nonce_hex).is_err(),
        "Tampered sealed stream ciphertext must be rejected"
    );

    // Wrong key -> must fail closed
    let wrong_key_hex = encode_hex(&[0x11u8; 32]);
    assert!(
        WasmCidVerifier::decrypt_and_decompress(&sealed_bytes, &wrong_key_hex, &nonce_hex).is_err(),
        "Decryption with wrong key must fail closed"
    );

    // 2. Raw AES-GCM-SIV format
    let encrypted = aes_gcm_siv_encrypt_sequential(&key, &nonce, b"", original_payload).unwrap();
    let mut raw_with_tag = encrypted.ciphertext;
    raw_with_tag.extend_from_slice(&encrypted.tag);

    let recovered_raw =
        WasmCidVerifier::decrypt_and_decompress(&raw_with_tag, &key_hex, &nonce_hex).unwrap();
    assert_eq!(recovered_raw, original_payload);
}

#[test]
fn test_c_abi_exports() {
    unsafe {
        let raw_data = b"Testing C ABI exports for WASM Service Worker";
        let cid = Cid::sha2_256(codec::RAW, raw_data);
        let cid_str = cid.to_string();

        let data_ptr = todo_wasm_alloc(raw_data.len());
        std::ptr::copy_nonoverlapping(raw_data.as_ptr(), data_ptr, raw_data.len());

        let cid_bytes = cid_str.as_bytes();
        let cid_ptr = todo_wasm_alloc(cid_bytes.len());
        std::ptr::copy_nonoverlapping(cid_bytes.as_ptr(), cid_ptr, cid_bytes.len());

        let verify_res = todo_wasm_verify_block(data_ptr, raw_data.len(), cid_ptr, cid_bytes.len());
        assert_eq!(verify_res, 1);

        // Mutate byte in buffer
        *data_ptr ^= 0xff;
        let tampered_res =
            todo_wasm_verify_block(data_ptr, raw_data.len(), cid_ptr, cid_bytes.len());
        assert_eq!(tampered_res, 0);

        todo_wasm_free(data_ptr, raw_data.len());
        todo_wasm_free(cid_ptr, cid_bytes.len());

        // Parse manifest C-ABI
        let manifest = ObjectManifest::new(
            "abi-test-stream",
            vec![BlockLink {
                cid: cid.clone(),
                size: raw_data.len() as u64,
            }],
        )
        .unwrap();
        let dag_json = manifest.to_dag_json();
        let manifest_ptr = todo_wasm_alloc(dag_json.len());
        std::ptr::copy_nonoverlapping(dag_json.as_ptr(), manifest_ptr, dag_json.len());

        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let manifest_res =
            todo_wasm_parse_manifest(manifest_ptr, dag_json.len(), &mut out_ptr, &mut out_len);
        assert!(manifest_res > 0);
        let out_slice = std::slice::from_raw_parts(out_ptr, out_len);
        let out_str = std::str::from_utf8(out_slice).unwrap();
        assert!(out_str.contains("abi-test-stream"));
        todo_wasm_free(manifest_ptr, dag_json.len());
        todo_wasm_free(out_ptr, out_len);

        // Decrypt C-ABI
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let enc = aes_gcm_siv_encrypt_sequential(&key, &nonce, b"", b"C-ABI Decrypt Text").unwrap();
        let mut ct_tag = enc.ciphertext;
        ct_tag.extend_from_slice(&enc.tag);

        let ct_ptr = todo_wasm_alloc(ct_tag.len());
        std::ptr::copy_nonoverlapping(ct_tag.as_ptr(), ct_ptr, ct_tag.len());

        let key_hex = encode_hex(&key);
        let nonce_hex = encode_hex(&nonce);

        let mut dec_ptr: *mut u8 = std::ptr::null_mut();
        let mut dec_len: usize = 0;
        let dec_res = todo_wasm_decrypt_decompress(
            ct_ptr,
            ct_tag.len(),
            key_hex.as_ptr(),
            key_hex.len(),
            nonce_hex.as_ptr(),
            nonce_hex.len(),
            &mut dec_ptr,
            &mut dec_len,
        );
        assert_eq!(dec_res, 18);
        let dec_slice = std::slice::from_raw_parts(dec_ptr, dec_len);
        assert_eq!(dec_slice, b"C-ABI Decrypt Text");

        todo_wasm_free(ct_ptr, ct_tag.len());
        todo_wasm_free(dec_ptr, dec_len);
    }
}
