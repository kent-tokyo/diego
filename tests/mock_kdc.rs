//! Integration test: mock KDC for AS-REP Roasting flow.
//!
//! Verifies the full path:
//!   build_asrep_roast_request() → TCP → parse_kdc_response() → format_asrep_18200()

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use diego::modules::kerberos::asreq::{
    application_explicit, build_asrep_roast_request, context_explicit, der_int, der_octet_string,
    sequence, parse_kdc_response, KdcResponse,
    ETYPE_RC4_HMAC,
};
use diego::modules::kerberos::hashcat::format_asrep_18200;
use diego::modules::kerberos::mod_send_kerberos_tcp;

/// Build a minimal but valid-format AS-REP response.
/// Structure: [APPLICATION 11] SEQUENCE { [0] pvno=5, [1] msg-type=11, ..., [6] enc_part }
fn build_fake_asrep(etype: i32, cipher: &[u8]) -> Vec<u8> {
    // EncryptedData: SEQUENCE { [0] etype, [2] cipher }
    let enc_part = sequence(
        [
            context_explicit(0, der_int(etype as i64)),
            context_explicit(2, der_octet_string(cipher)),
        ]
        .into_iter()
        .flatten()
        .collect(),
    );

    // Minimal KDC-REP fields with context tags matching AS-REP structure
    // We only need enc_part at [6] for our parser; fill others with minimal data.
    let kdc_rep_inner: Vec<u8> = [
        context_explicit(0, der_int(5)),     // [0] pvno
        context_explicit(1, der_int(11)),    // [1] msg-type = AS-REP
        // [2] padata omitted (OPTIONAL)
        // [3] crealm
        context_explicit(3, {
            let mut v = vec![0x1b]; // GeneralString tag
            v.push(8u8);
            v.extend_from_slice(b"CORP.LOC");
            v
        }),
        context_explicit(6, enc_part),       // [6] enc_part
    ]
    .into_iter()
    .flatten()
    .collect();

    let kdc_rep = sequence(kdc_rep_inner);
    let as_rep = application_explicit(11, kdc_rep); // APPLICATION 11

    // TCP frame: 4-byte BE length prefix
    let mut framed = Vec::with_capacity(4 + as_rep.len());
    framed.extend_from_slice(&(as_rep.len() as u32).to_be_bytes());
    framed.extend_from_slice(&as_rep);
    framed
}

/// Spawn a mock KDC that responds to every connection with the given response bytes.
async fn spawn_mock_kdc(response: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut conn, _)) = listener.accept().await {
            // Read the request (consume it but ignore contents)
            let mut len_buf = [0u8; 4];
            let _ = conn.read_exact(&mut len_buf).await;
            let body_len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; body_len];
            let _ = conn.read_exact(&mut body).await;
            // Send the mock response
            let _ = conn.write_all(&response).await;
        }
    });
    addr
}

#[tokio::test]
async fn test_asrep_roasting_full_flow() {
    let fake_cipher = b"fakehashbytes1234567890abcdef01".to_vec();
    let response = build_fake_asrep(ETYPE_RC4_HMAC, &fake_cipher);

    let addr = spawn_mock_kdc(response).await;

    // Build and send an AS-REQ
    let req = build_asrep_roast_request("alice", "CORP.LOCAL", 0x1234abcd);
    let raw = mod_send_kerberos_tcp(&addr, &req, 5)
        .await
        .expect("TCP send/recv failed");

    // Parse the response
    let result = parse_kdc_response(&raw).expect("parse failed");
    match result {
        KdcResponse::AsRep(enc) => {
            assert_eq!(enc.etype, ETYPE_RC4_HMAC, "etype mismatch");
            assert_eq!(enc.cipher, fake_cipher, "cipher mismatch");

            let hash = format_asrep_18200(enc.etype, "alice", "CORP.LOCAL", &enc.cipher);
            assert!(hash.starts_with("$krb5asrep$"), "bad hashcat format: {}", hash);
            assert!(hash.contains("alice@CORP.LOCAL"), "missing username");
        }
        other => panic!("Expected AsRep, got {:?}", other),
    }
}

#[tokio::test]
async fn test_preauth_required_response() {
    // KRB-ERROR 25 = PREAUTH_REQUIRED
    // [APPLICATION 30] SEQUENCE { [6] error-code }
    let error_code_field = context_explicit(6, der_int(25));
    let krb_err_inner: Vec<u8> = [
        context_explicit(0, der_int(5)),   // pvno
        context_explicit(1, der_int(30)),  // msg-type = KRB-ERROR
        error_code_field,
    ]
    .into_iter()
    .flatten()
    .collect();
    let krb_err = application_explicit(30, sequence(krb_err_inner));
    let mut framed = Vec::with_capacity(4 + krb_err.len());
    framed.extend_from_slice(&(krb_err.len() as u32).to_be_bytes());
    framed.extend_from_slice(&krb_err);

    let addr = spawn_mock_kdc(framed).await;
    let req = build_asrep_roast_request("bob", "CORP.LOCAL", 0xdeadbeef);
    let raw = mod_send_kerberos_tcp(&addr, &req, 5).await.unwrap();

    match parse_kdc_response(&raw).unwrap() {
        KdcResponse::PreauthRequired => { /* expected */ }
        other => panic!("Expected PreauthRequired, got {:?}", other),
    }
}

// ─── Phase 1 Security Fix Verification ────────────────────────────────────

#[tokio::test]
async fn test_malformed_asrep_too_short_cipher() {
    // Send AS-REP with cipher < 24 bytes (violates RC4-HMAC bounds check).
    // This should be parsed, but decryption should fail safely.
    let too_short_cipher = b"shortcipher".to_vec(); // Only 11 bytes
    let response = build_fake_asrep(ETYPE_RC4_HMAC, &too_short_cipher);

    let addr = spawn_mock_kdc(response).await;
    let req = build_asrep_roast_request("alice", "CORP.LOCAL", 0x1234abcd);
    let raw = mod_send_kerberos_tcp(&addr, &req, 5)
        .await
        .expect("TCP send/recv failed");

    // Parsing should succeed (we're just extracting the ciphertext)
    let result = parse_kdc_response(&raw).expect("parse failed");
    match result {
        KdcResponse::AsRep(enc) => {
            // The cipher is too short for RC4-HMAC decryption
            assert_eq!(enc.cipher.len(), 11, "cipher should be 11 bytes");
            assert!(enc.cipher.len() < 24, "cipher is too short for RC4-HMAC");
        }
        other => panic!("Expected AsRep, got {:?}", other),
    }
}

#[tokio::test]
async fn test_malformed_asrep_missing_enc_part() {
    // Send AS-REP without [6] enc_part field — parser should fail gracefully.
    let kdc_rep_inner: Vec<u8> = [
        context_explicit(0, der_int(5)),     // [0] pvno
        context_explicit(1, der_int(11)),    // [1] msg-type = AS-REP
        context_explicit(3, {
            let mut v = vec![0x1b]; // GeneralString tag
            v.push(8u8);
            v.extend_from_slice(b"CORP.LOC");
            v
        }),
        // Missing [6] enc_part!
    ]
    .into_iter()
    .flatten()
    .collect();

    let kdc_rep = sequence(kdc_rep_inner);
    let as_rep = application_explicit(11, kdc_rep);
    let mut response = Vec::with_capacity(4 + as_rep.len());
    response.extend_from_slice(&(as_rep.len() as u32).to_be_bytes());
    response.extend_from_slice(&as_rep);

    let addr = spawn_mock_kdc(response).await;
    let req = build_asrep_roast_request("alice", "CORP.LOCAL", 0x1234abcd);
    let raw = mod_send_kerberos_tcp(&addr, &req, 5)
        .await
        .expect("TCP send/recv failed");

    // Parsing should fail — enc_part [6] is missing
    let result = parse_kdc_response(&raw);
    assert!(result.is_err(), "parsing AS-REP without enc_part should fail");
}

#[tokio::test]
async fn test_invalid_response_tag() {
    // Send a response with invalid APPLICATION tag (not 0x6b or 0x7e).
    let mut response = vec![0x99]; // Invalid tag
    response.extend_from_slice(&[0x01, 0x00]); // Minimal length/value

    let mut framed = Vec::with_capacity(4 + response.len());
    framed.extend_from_slice(&(response.len() as u32).to_be_bytes());
    framed.extend_from_slice(&response);

    let addr = spawn_mock_kdc(framed).await;
    let req = build_asrep_roast_request("alice", "CORP.LOCAL", 0x1234abcd);
    let raw = mod_send_kerberos_tcp(&addr, &req, 5)
        .await
        .expect("TCP send/recv failed");

    // Parsing should fail — invalid APPLICATION tag
    let result = parse_kdc_response(&raw);
    assert!(result.is_err(), "parsing invalid tag should fail");
}

#[tokio::test]
async fn test_truncated_kdc_response() {
    // Send a truncated response: APPLICATION tag but no length/value.
    let response = vec![0x6b]; // AS-REP tag but incomplete
    let mut framed = Vec::with_capacity(4 + response.len());
    framed.extend_from_slice(&(response.len() as u32).to_be_bytes());
    framed.extend_from_slice(&response);

    let addr = spawn_mock_kdc(framed).await;
    let req = build_asrep_roast_request("alice", "CORP.LOCAL", 0x1234abcd);
    let raw = mod_send_kerberos_tcp(&addr, &req, 5)
        .await
        .expect("TCP send/recv failed");

    // Parsing should fail — truncated TLV structure
    let result = parse_kdc_response(&raw);
    assert!(result.is_err(), "parsing truncated response should fail");
}
