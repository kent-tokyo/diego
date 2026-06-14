//! Kerberos crypto primitives — pure Rust, zero C dependencies.
//!
//! MD4 (RFC 1320), RC4-HMAC (RFC 4757), NT hash (NTLM).

use hmac::{Hmac, Mac};
use md5::Md5;
type HmacMd5 = Hmac<Md5>;

// ─── MD4 (RFC 1320) ──────────────────────────────────────────────────────────
//
// All 48 steps written explicitly — no macros, no inner function name conflicts.

pub fn md4(msg: &[u8]) -> [u8; 16] {
    let bit_len = (msg.len() as u64) * 8;
    let mut p = msg.to_vec();
    p.push(0x80);
    while p.len() % 64 != 56 { p.push(0x00); }
    p.extend_from_slice(&bit_len.to_le_bytes());

    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xEFCD_AB89;
    let mut c: u32 = 0x98BA_DCFE;
    let mut d: u32 = 0x1032_5476;

    for blk in p.chunks_exact(64) {
        // Load message words
        let w0  = u32::from_le_bytes([blk[ 0],blk[ 1],blk[ 2],blk[ 3]]);
        let w1  = u32::from_le_bytes([blk[ 4],blk[ 5],blk[ 6],blk[ 7]]);
        let w2  = u32::from_le_bytes([blk[ 8],blk[ 9],blk[10],blk[11]]);
        let w3  = u32::from_le_bytes([blk[12],blk[13],blk[14],blk[15]]);
        let w4  = u32::from_le_bytes([blk[16],blk[17],blk[18],blk[19]]);
        let w5  = u32::from_le_bytes([blk[20],blk[21],blk[22],blk[23]]);
        let w6  = u32::from_le_bytes([blk[24],blk[25],blk[26],blk[27]]);
        let w7  = u32::from_le_bytes([blk[28],blk[29],blk[30],blk[31]]);
        let w8  = u32::from_le_bytes([blk[32],blk[33],blk[34],blk[35]]);
        let w9  = u32::from_le_bytes([blk[36],blk[37],blk[38],blk[39]]);
        let w10 = u32::from_le_bytes([blk[40],blk[41],blk[42],blk[43]]);
        let w11 = u32::from_le_bytes([blk[44],blk[45],blk[46],blk[47]]);
        let w12 = u32::from_le_bytes([blk[48],blk[49],blk[50],blk[51]]);
        let w13 = u32::from_le_bytes([blk[52],blk[53],blk[54],blk[55]]);
        let w14 = u32::from_le_bytes([blk[56],blk[57],blk[58],blk[59]]);
        let w15 = u32::from_le_bytes([blk[60],blk[61],blk[62],blk[63]]);

        let (aa, bb, cc, dd) = (a, b, c, d);

        // F(x,y,z) = (x & y) | (!x & z)
        #[inline(always)] fn f(x:u32,y:u32,z:u32)->u32 { (x&y)|(!x&z) }
        // G(x,y,z) = (x & y) | (x & z) | (y & z)
        #[inline(always)] fn g(x:u32,y:u32,z:u32)->u32 { (x&y)|(x&z)|(y&z) }
        // H(x,y,z) = x ^ y ^ z
        #[inline(always)] fn h(x:u32,y:u32,z:u32)->u32 { x^y^z }

        // Round 1 — F, no constant
        a=a.wrapping_add(f(b,c,d)).wrapping_add(w0 ).rotate_left( 3);
        d=d.wrapping_add(f(a,b,c)).wrapping_add(w1 ).rotate_left( 7);
        c=c.wrapping_add(f(d,a,b)).wrapping_add(w2 ).rotate_left(11);
        b=b.wrapping_add(f(c,d,a)).wrapping_add(w3 ).rotate_left(19);
        a=a.wrapping_add(f(b,c,d)).wrapping_add(w4 ).rotate_left( 3);
        d=d.wrapping_add(f(a,b,c)).wrapping_add(w5 ).rotate_left( 7);
        c=c.wrapping_add(f(d,a,b)).wrapping_add(w6 ).rotate_left(11);
        b=b.wrapping_add(f(c,d,a)).wrapping_add(w7 ).rotate_left(19);
        a=a.wrapping_add(f(b,c,d)).wrapping_add(w8 ).rotate_left( 3);
        d=d.wrapping_add(f(a,b,c)).wrapping_add(w9 ).rotate_left( 7);
        c=c.wrapping_add(f(d,a,b)).wrapping_add(w10).rotate_left(11);
        b=b.wrapping_add(f(c,d,a)).wrapping_add(w11).rotate_left(19);
        a=a.wrapping_add(f(b,c,d)).wrapping_add(w12).rotate_left( 3);
        d=d.wrapping_add(f(a,b,c)).wrapping_add(w13).rotate_left( 7);
        c=c.wrapping_add(f(d,a,b)).wrapping_add(w14).rotate_left(11);
        b=b.wrapping_add(f(c,d,a)).wrapping_add(w15).rotate_left(19);

        // Round 2 — G, constant 0x5A827999
        const K2:u32=0x5A82_7999;
        a=a.wrapping_add(g(b,c,d)).wrapping_add(w0 ).wrapping_add(K2).rotate_left( 3);
        d=d.wrapping_add(g(a,b,c)).wrapping_add(w4 ).wrapping_add(K2).rotate_left( 5);
        c=c.wrapping_add(g(d,a,b)).wrapping_add(w8 ).wrapping_add(K2).rotate_left( 9);
        b=b.wrapping_add(g(c,d,a)).wrapping_add(w12).wrapping_add(K2).rotate_left(13);
        a=a.wrapping_add(g(b,c,d)).wrapping_add(w1 ).wrapping_add(K2).rotate_left( 3);
        d=d.wrapping_add(g(a,b,c)).wrapping_add(w5 ).wrapping_add(K2).rotate_left( 5);
        c=c.wrapping_add(g(d,a,b)).wrapping_add(w9 ).wrapping_add(K2).rotate_left( 9);
        b=b.wrapping_add(g(c,d,a)).wrapping_add(w13).wrapping_add(K2).rotate_left(13);
        a=a.wrapping_add(g(b,c,d)).wrapping_add(w2 ).wrapping_add(K2).rotate_left( 3);
        d=d.wrapping_add(g(a,b,c)).wrapping_add(w6 ).wrapping_add(K2).rotate_left( 5);
        c=c.wrapping_add(g(d,a,b)).wrapping_add(w10).wrapping_add(K2).rotate_left( 9);
        b=b.wrapping_add(g(c,d,a)).wrapping_add(w14).wrapping_add(K2).rotate_left(13);
        a=a.wrapping_add(g(b,c,d)).wrapping_add(w3 ).wrapping_add(K2).rotate_left( 3);
        d=d.wrapping_add(g(a,b,c)).wrapping_add(w7 ).wrapping_add(K2).rotate_left( 5);
        c=c.wrapping_add(g(d,a,b)).wrapping_add(w11).wrapping_add(K2).rotate_left( 9);
        b=b.wrapping_add(g(c,d,a)).wrapping_add(w15).wrapping_add(K2).rotate_left(13);

        // Round 3 — H, constant 0x6ED9EBA1
        const K3:u32=0x6ED9_EBA1;
        a=a.wrapping_add(h(b,c,d)).wrapping_add(w0 ).wrapping_add(K3).rotate_left( 3);
        d=d.wrapping_add(h(a,b,c)).wrapping_add(w8 ).wrapping_add(K3).rotate_left( 9);
        c=c.wrapping_add(h(d,a,b)).wrapping_add(w4 ).wrapping_add(K3).rotate_left(11);
        b=b.wrapping_add(h(c,d,a)).wrapping_add(w12).wrapping_add(K3).rotate_left(15);
        a=a.wrapping_add(h(b,c,d)).wrapping_add(w2 ).wrapping_add(K3).rotate_left( 3);
        d=d.wrapping_add(h(a,b,c)).wrapping_add(w10).wrapping_add(K3).rotate_left( 9);
        c=c.wrapping_add(h(d,a,b)).wrapping_add(w6 ).wrapping_add(K3).rotate_left(11);
        b=b.wrapping_add(h(c,d,a)).wrapping_add(w14).wrapping_add(K3).rotate_left(15);
        a=a.wrapping_add(h(b,c,d)).wrapping_add(w1 ).wrapping_add(K3).rotate_left( 3);
        d=d.wrapping_add(h(a,b,c)).wrapping_add(w9 ).wrapping_add(K3).rotate_left( 9);
        c=c.wrapping_add(h(d,a,b)).wrapping_add(w5 ).wrapping_add(K3).rotate_left(11);
        b=b.wrapping_add(h(c,d,a)).wrapping_add(w13).wrapping_add(K3).rotate_left(15);
        a=a.wrapping_add(h(b,c,d)).wrapping_add(w3 ).wrapping_add(K3).rotate_left( 3);
        d=d.wrapping_add(h(a,b,c)).wrapping_add(w11).wrapping_add(K3).rotate_left( 9);
        c=c.wrapping_add(h(d,a,b)).wrapping_add(w7 ).wrapping_add(K3).rotate_left(11);
        b=b.wrapping_add(h(c,d,a)).wrapping_add(w15).wrapping_add(K3).rotate_left(15);

        a=a.wrapping_add(aa);
        b=b.wrapping_add(bb);
        c=c.wrapping_add(cc);
        d=d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[ 0.. 4].copy_from_slice(&a.to_le_bytes());
    out[ 4.. 8].copy_from_slice(&b.to_le_bytes());
    out[ 8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

// ─── NT hash ─────────────────────────────────────────────────────────────────

pub fn ntlm_hash(password: &str) -> [u8; 16] {
    let mut utf16le = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        utf16le.push((unit & 0xff) as u8);
        utf16le.push((unit >> 8) as u8);
    }
    md4(&utf16le)
}

// ─── RC4-HMAC (RFC 4757) ─────────────────────────────────────────────────────

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn rc4_inplace(key: &[u8], data: &mut [u8]) {
    if key.is_empty() {
        return; // RC4 with empty key is no-op
    }
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    for byte in data.iter_mut() {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        *byte ^= s[(s[i] as usize + s[j] as usize) % 256];
    }
}

pub fn rc4_hmac_encrypt(key: &[u8], key_usage: u32, plaintext: &[u8]) -> Vec<u8> {
    let k1 = hmac_md5(key, &key_usage.to_le_bytes());
    let confounder: [u8; 8] = rand::random();
    let mut t_input = confounder.to_vec();
    t_input.extend_from_slice(plaintext);
    let t = hmac_md5(&k1, &t_input);
    let k3 = hmac_md5(&k1, &t);
    rc4_inplace(&k3, &mut t_input);
    let mut out = t.to_vec();
    out.extend_from_slice(&t_input);
    out
}

pub fn rc4_hmac_decrypt(key: &[u8], key_usage: u32, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if ciphertext.len() < 24 {
        anyhow::bail!("RC4-HMAC ciphertext too short");
    }
    let k1 = hmac_md5(key, &key_usage.to_le_bytes());
    let (checksum, encrypted) = ciphertext.split_at(16);
    let k3 = hmac_md5(&k1, checksum);
    let mut plaintext = encrypted.to_vec();
    rc4_inplace(&k3, &mut plaintext);
    if hmac_md5(&k1, &plaintext) != checksum {
        anyhow::bail!("RC4-HMAC checksum mismatch");
    }
    if plaintext.len() < 8 {
        anyhow::bail!("RC4-HMAC plaintext too short (missing 8-byte confounder)");
    }
    Ok(plaintext[8..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md4_empty() {
        assert_eq!(hex::encode(md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_md4_a() {
        assert_eq!(hex::encode(md4(b"a")), "bde52cb31de33e46245e05fbdbd6fb24");
    }

    #[test]
    fn test_md4_abc() {
        assert_eq!(hex::encode(md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
    }

    #[test]
    fn test_md4_message_digest() {
        // RFC 1320 vector: MD4("message digest") = d9130a8164549fe818874806e1c7014b
        assert_eq!(hex::encode(md4(b"message digest")), "d9130a8164549fe818874806e1c7014b");
    }

    #[test]
    fn test_md4_password_utf16le_consistency() {
        // "Password" (capital P) UTF-16LE bytes
        let p: &[u8] = &[0x50,0x00,0x61,0x00,0x73,0x00,0x73,0x00,
                          0x77,0x00,0x6f,0x00,0x72,0x00,0x64,0x00];
        // Both MD4 implementations must agree
        use md4::Md4;
        use digest::Digest;
        let crate_out = <Md4 as Digest>::digest(p);
        let mut crate_hash = [0u8; 16];
        crate_hash.copy_from_slice(&crate_out);
        assert_eq!(md4(p), crate_hash, "inline MD4 must match md4 crate");
        // Case-sensitivity: "Password" ≠ "password"
        let lowercase_hash = ntlm_hash("password");
        assert_ne!(md4(p), lowercase_hash, "NT hashes must differ by case");
    }

    #[test]
    fn test_utf16le_encoding() {
        let mut utf16le = Vec::new();
        for unit in "Password".encode_utf16() {
            utf16le.push((unit & 0xff) as u8);
            utf16le.push((unit >> 8) as u8);
        }
        let expected: &[u8] = &[0x50,0x00,0x61,0x00,0x73,0x00,0x73,0x00,
                                  0x77,0x00,0x6f,0x00,0x72,0x00,0x64,0x00];
        assert_eq!(utf16le, expected, "UTF-16LE: {}", hex::encode(&utf16le));
    }

    #[test]
    fn test_ntlm_hash_known_vector() {
        // 8846f7eaee8fb117ad06bdd830b7586c is the NT hash of "password" (all lowercase)
        // "Password" (capital P) has a different NT hash — both are correct per our MD4
        assert_eq!(hex::encode(ntlm_hash("password")), "8846f7eaee8fb117ad06bdd830b7586c",
            "NT hash of 'password' (lowercase)");
        // Verify "Password" (capital P) gives a different but consistent hash (both impls agree)
        let pwd_hash = ntlm_hash("Password");
        use md4::Md4; use digest::Digest;
        let utf16le: Vec<u8> = "Password".encode_utf16()
            .flat_map(|c| [((c & 0xff) as u8), ((c >> 8) as u8)]).collect();
        let crate_out = <Md4 as Digest>::digest(&utf16le);
        let mut crate_hash = [0u8; 16];
        crate_hash.copy_from_slice(&crate_out);
        assert_eq!(pwd_hash, crate_hash, "Both MD4 impls must agree on 'Password'");
    }

    #[test]
    fn test_ntlm_hash_empty() {
        assert_eq!(hex::encode(ntlm_hash("")), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_rc4_roundtrip() {
        let key = ntlm_hash("TestPass1");
        let pt = b"hello kerberos world";
        let ct = rc4_hmac_encrypt(&key, 1, pt);
        assert_eq!(rc4_hmac_decrypt(&key, 1, &ct).unwrap(), pt);
    }

    #[test]
    fn test_rc4_wrong_key_fails() {
        let ct = rc4_hmac_encrypt(&ntlm_hash("correct"), 1, b"secret");
        assert!(rc4_hmac_decrypt(&ntlm_hash("wrong"), 1, &ct).is_err());
    }

    // ─── RC4-HMAC bounds checks (Phase 1 security fix) ───────────────────────
    #[test]
    fn test_rc4_ciphertext_too_short() {
        let key = ntlm_hash("password");
        // Minimum valid ciphertext: 16-byte checksum + 8-byte confounder = 24 bytes
        assert!(rc4_hmac_decrypt(&key, 1, &[0u8; 23]).is_err(), "23 bytes should fail");
        assert!(rc4_hmac_decrypt(&key, 1, &[0u8; 1]).is_err(), "1 byte should fail");
        assert!(rc4_hmac_decrypt(&key, 1, &[]).is_err(), "empty should fail");
    }

    #[test]
    fn test_rc4_ciphertext_exactly_minimum() {
        // 24 bytes: 16-byte checksum + 8-byte encrypted payload (confounder)
        // Will fail checksum but shouldn't panic
        let key = ntlm_hash("password");
        let ct = vec![0u8; 24];
        let result = rc4_hmac_decrypt(&key, 1, &ct);
        assert!(result.is_err(), "24-byte ciphertext with wrong checksum should fail gracefully");
    }

    #[test]
    fn test_rc4_empty_key_no_panic() {
        // RC4 with empty key should not panic (regression test for modulo-by-zero)
        let mut data = vec![1, 2, 3, 4, 5];
        rc4_inplace(&[], &mut data);
        // Empty key → no-op, data unchanged
        assert_eq!(data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_rc4_hmac_checksum_failure() {
        let key = ntlm_hash("password");
        let pt = b"test data";
        let mut ct = rc4_hmac_encrypt(&key, 1, pt);
        // Corrupt the checksum (first 16 bytes)
        ct[0] ^= 0xFF;
        assert!(rc4_hmac_decrypt(&key, 1, &ct).is_err(), "corrupted checksum should fail");
    }

    #[test]
    fn test_rc4_hmac_decrypt_invalid_key_usage() {
        let key = ntlm_hash("password");
        let pt = b"test data";
        let ct = rc4_hmac_encrypt(&key, 1, pt);
        // Decrypt with wrong key usage value
        assert!(rc4_hmac_decrypt(&key, 2, &ct).is_err(), "wrong key usage should fail");
    }
}
