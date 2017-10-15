/// Rust bindings for HACL* crypto library
///
/// HACL* is available at: https://github.com/mitls/hacl-star
///
/// This library requires a libhacl.so installed in /usr/local/lib and
/// have the environmental variable set with `export LD_LIBRARY_PATH=/usr/local/lib`
///

const MAC_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const SIGN_LEN: usize = 64;
const HASH_LEN: usize = 64;

use std::ptr;

#[link(name = "hacl")]
extern "C" {
    fn Chacha20Poly1305_aead_encrypt(c: *const u8,
                                     mac: *const u8,
                                     m: *const u8,
                                     mlen: u32,
                                     aad1: *const u8,
                                     aadlen: u32,
                                     k1: *const u8,
                                     n1: *const u8)
                                     -> u32;
}


#[link(name = "hacl")]
extern "C" {
    fn Chacha20Poly1305_aead_decrypt(m: *const u8,
                                     c: *const u8,
                                     mlen: u32,
                                     mac: *const u8,
                                     aad1: *const u8,
                                     aadlen: u32,
                                     k1: *const u8,
                                     n1: *const u8)
                                     -> u32;
}


#[link(name = "hacl")]
extern "C" {
    fn Curve25519_crypto_scalarmult(mypublic: *const u8, secret: *const u8, basepoint: *const u8);
}


#[link(name = "hacl")]
extern "C" {
    fn Ed25519_sign(signature: *const u8, secret: *const u8, msg: *const u8, len: u32);
}

#[link(name = "hacl")]
extern "C" {
    fn Ed25519_verify(public: *const u8, msg: *const u8, mlen: u32, signature: *const u8) -> bool;
}

#[link(name = "hacl")]
extern "C" {
    fn Ed25519_secret_to_public(out: *const u8, secret: *const u8);
}


#[link(name = "hacl")]
extern "C" {
    fn SHA2_512_hash(hash: *const u8, input: *const u8, input_len: u32);
}


/// hash: resulting hash, 64 bytes
/// input: input to be hashed, `input_len` long
/// input_len: input length
pub fn sha2_512_hash(hash: &mut [u8], input: &[u8]) -> Result<(), String> {
    if hash.len() != HASH_LEN {
        return Err(String::from("Hash length error"));
    }

    if input.is_empty() {
        return Err(String::from("Can't use an empty input message"));
    }

    let input_len = input.len() as u32;

    unsafe {
        SHA2_512_hash(hash.as_ptr(), input.as_ptr(), input_len);
    }

    return Ok(());
}



/// signature: 64 bytes
/// secret: secret key, 32 bytes
/// msg: message to sign
/// len: lentgh of the message
pub fn ed25519_sign(signature: &mut [u8], secret_key: &[u8], message: &[u8]) -> Result<(), String> {
    if secret_key.len() != KEY_LEN {
        return Err(String::from("Public key length error"));
    }
    if signature.len() != SIGN_LEN {
        return Err(String::from("Signature length error"));
    }

    if message.is_empty() {
        return Err(String::from("Can't use an empty message"));
    }

    let mlen = message.len() as u32;

    unsafe {
        Ed25519_sign(signature.as_ptr(),
                     secret_key.as_ptr(),
                     message.as_ptr(),
                     mlen);
    }


    return Ok(());
}

/// Given a public key, message and tag (signature) return 0 if the signature is correct, non-zero otherwize
/// fn Ed25519_verify(public: *const u8, msg: *const u8, mlen: u32, signature: *const u8) -> bool;
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, String> {
    if signature.len() != SIGN_LEN {
        return Err(String::from("Signature length error"));
    }
    if public_key.len() != KEY_LEN {
        return Err(String::from("Public key length error"));
    }
    if message.is_empty() {
        return Err(String::from("Can't use an empty message"));
    }

    let mlen = message.len() as u32;

    let val = unsafe {
        Ed25519_verify(public_key.as_ptr(),
                       message.as_ptr(),
                       mlen,
                       signature.as_ptr())
    };
    return Ok(val);
}

/// calculate public key given a secret key
pub fn ed25519_secret_to_public(public_key: &mut [u8], secret_key: &[u8]) -> Result<(), String> {
    if secret_key.len() != KEY_LEN {
        return Err(String::from("Public key length error"));
    }
    if public_key.len() != KEY_LEN {
        return Err(String::from("Public key length error"));
    }

    unsafe {
        Ed25519_secret_to_public(public_key.as_ptr(), secret_key.as_ptr());
    }

    return Ok(());
}

/// mypublic: generated public key, 32 bytes
/// secret: secret key, 32 bytes
/// basepoint: initial point, 32 bytes, default is 9
pub fn curve25519_crypto_scalarmult(public_key: &mut [u8],
                                    secret_key: &[u8],
                                    basepoint: &[u8])
                                    -> Result<(), String> {
    if public_key.len() != KEY_LEN {
        return Err(String::from("Public key length error"));
    }

    if secret_key.len() != KEY_LEN {
        return Err(String::from("Secret key length error"));
    }

    if basepoint.len() != KEY_LEN {
        return Err(String::from("Basepoint length error"));
    }

    unsafe {
        Curve25519_crypto_scalarmult(public_key.as_ptr(), secret_key.as_ptr(), basepoint.as_ptr());
    }

    return Ok(());
}

/// c: ciphertext (`mlen` long)
/// mac: authenticaton tag, 16 bytes
/// mlen: plaintext length
/// m: plaintext (`mlen` long)
/// aad1: additional authentication data, `aadlen` long
/// aadlen: length of additional auth data
/// k1: key, 32 bytes
/// n1: nonce, 12 bytes
pub fn chacha20poly1305_aead_decrypt(message: &mut [u8],
                                     mac: &[u8],
                                     ciphertext: &[u8],
                                     aad: &[u8],
                                     key: &[u8],
                                     nonce: &[u8])
                                     -> Result<bool, String> {
    if mac.len() != MAC_LEN {
        return Err(String::from("Mac length error"));
    }

    if key.len() != KEY_LEN {
        return Err(String::from("Key length error"));
    }

    if nonce.len() != NONCE_LEN {
        return Err(String::from("Nonce length error"));
    }

    if message.is_empty() {
        return Err(String::from("Can't use an empty message"));
    }

    if ciphertext.len() != message.len() {
        return Err(String::from("Message and ciphertext have different lengths"));
    }

    let mlen = message.len() as u32;
    let aadlen = aad.len() as u32;

    let aadptr = if aad.is_empty() {
        ptr::null()
    } else {
        aad.as_ptr()
    };


    let val = unsafe {
        Chacha20Poly1305_aead_decrypt(message.as_ptr(),
                                      ciphertext.as_ptr(),
                                      mlen,
                                      mac.as_ptr(),
                                      aadptr,
                                      aadlen,
                                      key.as_ptr(),
                                      nonce.as_ptr())
    };

    return match val {
        0 => Ok(true),
        _ => Ok(false),
    };
}

/// c: ciphertext (`mlen` long)
/// mac: authenticaton tag, 16 bytes
/// mlen: plaintext length
/// m: plaintext (`mlen` long)
/// aad1: additional authentication data, `aadlen` long
/// aadlen: length of additional auth data
/// k1: key, 32 bytes
/// n1: nonce, 12 bytes
pub fn chacha20poly1305_aead_encrypt(ciphertext: &mut [u8],
                                     mac: &mut [u8],
                                     message: &[u8],
                                     aad: &[u8],
                                     key: &[u8],
                                     nonce: &[u8])
                                     -> Result<bool, String> {
    if mac.len() != MAC_LEN {
        return Err(String::from("Mac length error"));
    }

    if key.len() != KEY_LEN {
        return Err(String::from("Key length error"));
    }

    if nonce.len() != NONCE_LEN {
        return Err(String::from("Nonce length error"));
    }

    if message.is_empty() {
        return Err(String::from("Can't use an empty message"));
    }

    if ciphertext.len() != message.len() {
        return Err(String::from("Message and ciphertext have different lengths"));
    }

    let mlen = message.len() as u32;
    let aadlen = aad.len() as u32;

    let aadptr = if aad.is_empty() {
        ptr::null()
    } else {
        aad.as_ptr()
    };


    let val = unsafe {
        Chacha20Poly1305_aead_encrypt(ciphertext.as_ptr(),
                                      mac.as_ptr(),
                                      message.as_ptr(),
                                      mlen,
                                      aadptr,
                                      aadlen,
                                      key.as_ptr(),
                                      nonce.as_ptr())
    };

    return match val {
        0 => Ok(true),
        _ => Ok(false),
    };
}


extern crate rand;

#[cfg(test)]
mod tests {
    use super::*;

    fn print_array(name: &str, b: &[u8]) {
        print!("{}[{}]=[", name, b.len());
        for i in b {
            print!("0x{:x},", i);
        }
        println!("];");
    }

    static KEY: [u8; 32] = [0x70, 0x3, 0xAA, 0xA, 0x8E, 0xE9, 0xA8, 0xFF, 0xD5, 0x46, 0x1E, 0xEC,
                            0x7C, 0xC1, 0xC1, 0xA1, 0x6A, 0x43, 0xC9, 0xD4, 0xB3, 0x2B, 0x94,
                            0x7E, 0x76, 0xF9, 0xD8, 0xE8, 0x1A, 0x31, 0x5D, 0xA8];

    static CIPHERTEXT: [u8; 2] = [0xd1, 0x67];
    static PLAINTEXT: [u8; 2] = [4, 3];
    static MAC: [u8; 16] = [0xcf, 0x77, 0x66, 0x79, 0x37, 0x51, 0x39, 0x87, 0x72, 0xb0, 0xe3,
                            0xc3, 0x9e, 0x8c, 0xef, 0x2f];
    static NONCE: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn test_chacha20poly1305_aead_encrypt() {
        let key: Vec<u8> = vec![0x70, 0x3, 0xAA, 0xA, 0x8E, 0xE9, 0xA8, 0xFF, 0xD5, 0x46, 0x1E,
                                0xEC, 0x7C, 0xC1, 0xC1, 0xA1, 0x6A, 0x43, 0xC9, 0xD4, 0xB3, 0x2B,
                                0x94, 0x7E, 0x76, 0xF9, 0xD8, 0xE8, 0x1A, 0x31, 0x5D, 0xA8];

        let mut mac: Vec<u8> = vec![0; 16];
        let aad = vec![];
        let mut ciphertext: Vec<u8> = vec![0, 0];
        let message = vec![4, 3];
        let nonce = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let success = match chacha20poly1305_aead_encrypt(ciphertext.as_mut_slice(),
                                                          mac.as_mut_slice(),
                                                          &message,
                                                          &aad,
                                                          &key,
                                                          &nonce) {
            Ok(val) => val,
            Err(msg) => panic!("Error! {}", msg),
        };

        assert_eq!(success, true);
        assert_eq!(mac, MAC);
        assert_eq!(ciphertext, CIPHERTEXT);
    }

    #[test]
    fn test_chacha20poly1305_aead_decrypt() {
        let mut plaintext = vec![0, 0];
        let aad = vec![];
        let success = match chacha20poly1305_aead_decrypt(plaintext.as_mut_slice(),
                                                          &MAC,
                                                          &CIPHERTEXT,
                                                          &aad,
                                                          &KEY,
                                                          &NONCE) {
            Ok(val) => val,
            Err(msg) => panic!("Error! {}", msg),
        };

        assert_eq!(success, true);
        assert_eq!(plaintext, PLAINTEXT);
    }

    #[test]
    fn test_curve25519_scalar_mult() {
        let mut basepoint: [u8; 32] = [0; 32];
        basepoint[0] = 9;

        let mut public_key: [u8; 32] = [0; 32];
        assert_eq!(curve25519_crypto_scalarmult(&mut public_key, &KEY, &basepoint),
                   Ok(()));

        print_array("Public key", &public_key);
        print_array("Private key", &KEY);
        print_array("Basepoint", &basepoint);
    }

    #[test]
    fn test_ed25519_sign() {
        let mut signature = vec![0; 64];
        let message = vec![0x6c, 0xe8, 0xaa, 0x8e, 0xed, 0x97, 0x50, 0xb5, 0xb8, 0x74, 0xf7, 0x29,
                           0x66, 0x91, 0x39, 0xce, 0xe0, 0xd6, 0x85, 0x9e, 0x48, 0xa3, 0xed, 0x3b,
                           0x5b, 0x7c, 0x89, 0xc1, 0x5a, 0x49, 0xf3, 0x7];

        assert_eq!(ed25519_sign(signature.as_mut_slice(), &KEY, &message),
                   Ok(()));
    }

    #[test]
    fn test_sha2_512_hash() {
        let mut hashed = vec![0; 64];

        assert_eq!(sha2_512_hash(hashed.as_mut_slice(), &KEY), Ok(()));
    }


    use std::thread;
    use std::sync::mpsc;
    use rand::os::OsRng;
    use rand::Rng;

    enum StatusA {
        Uninit,
        SendMessage1,
        WaitingForMessage2,
        SendMessage3,
        Running,
    }

    enum StatusB {
        Uninit,
        WaitingForMessage1,
        SendMessage2,
        WaitingForMEssage3,
        Running,
    }

    fn thread_a(tx: mpsc::Sender<Vec<u8>>, rx: mpsc::Receiver<Vec<u8>>) {
        // A
        // assymetric public key
        //        let p_a = vec![0x98, 0x99, 0x22, 0xFA, 0x6E, 0x87, 0x2B, 0xC1, 0x45, 0x84, 0x80, 0xAA,
        //                       0xF8, 0x65, 0xA5, 0xBA, 0xB8, 0x61, 0x85, 0x77, 0xC2, 0xEC, 0x37, 0xF9,
        //                       0xAF, 0xB3, 0xAE, 0x47, 0x83, 0x2C, 0xA4, 0x44];
        // assymetric secret key
        let q_a = vec![0xBC, 0xC9, 0xA5, 0x89, 0x7, 0x2B, 0x3C, 0x71, 0xBE, 0x86, 0x11, 0x1D,
                       0x85, 0x31, 0xB9, 0xBB, 0xF4, 0x29, 0x64, 0x9A, 0x7, 0xF1, 0xDB, 0x87,
                       0x5A, 0xA8, 0xF9, 0x49, 0x75, 0x8E, 0x3A, 0xD8];
        let mut p_a = vec![0; 32];
        ed25519_secret_to_public(p_a.as_mut_slice(), q_a.as_slice()).unwrap();
        print_array("A p_a", &p_a);

        // B
        // assymetric public key
        let p_b = vec![0xE4, 0xD5, 0x17, 0x13, 0xEB, 0xF8, 0x82, 0xCC, 0x7A, 0x90, 0x29, 0x14,
                       0x59, 0xCC, 0x84, 0x7E, 0xA2, 0xD3, 0xE9, 0x5E, 0x9E, 0x4, 0x26, 0x90,
                       0x83, 0x44, 0xE9, 0x5B, 0xA, 0xB7, 0x14, 0x42];

        let mut status = StatusA::Uninit;

        loop {
            // generate random
            let mut q_ae = vec![0; 32];
            let mut rng = OsRng::new().unwrap();
            rng.fill_bytes(q_ae.as_mut_slice());
            print_array("A q_ae", &q_ae);

            // basepoint
            let mut basepoint: [u8; 32] = [0; 32];
            basepoint[0] = 9;

            // 1. A generates an ephemeral (random) curve25519 key pair (Pae, Qae)
            let mut p_ae = vec![0; 32];
            assert_eq!(curve25519_crypto_scalarmult(p_ae.as_mut_slice(),
                                                    q_ae.as_slice(),
                                                    &basepoint),
                       Ok(()));
            print_array("A p_ae", &p_ae);

            // 1. and sends Pae.
            status = StatusA::SendMessage1;
            tx.send(p_ae.clone()).expect("A Couldn't send data");

            status = StatusA::WaitingForMessage2;
            let message2 = rx.recv().expect("A Couldn't receive data");
            print_array("A rx message2", &message2); // P_be[32], E(sig) [64],tag[16]

            // 7. A computes the shared secret: z = scalar_multiplication(Qae, Pbe)
            let mut p_be = vec![];
            p_be.extend_from_slice(&message2[0..32]);
            let mut z = vec![0; 32];
            assert_eq!(curve25519_crypto_scalarmult(z.as_mut_slice(),
                                                    q_ae.as_slice(),
                                                    p_be.as_slice()),
                       Ok(()));
            print_array("z", &z);

            // 4. A uses the key derivation function kdf(z,1) to compute Kb || Sb, kdf(z,0) to
            // compute Ka || Sa, and kdf(z,2) to compute Kclient || Sclient.
            // kdf(z,partyIdent) = SHA512( 0 || z || partyIdent)
            // (0 for A, 1 for B and 2 for key material returned to the callee)

            // kdf(z,0) to compute Ka || Sa
            let mut ka_sa = vec![0; 64];
            let mut input = z.clone();
            input.push(0);
            assert_eq!(sha2_512_hash(ka_sa.as_mut_slice(), input.as_slice()),
                       Ok(()));
            print_array("A k_a", &ka_sa[0..32]);
            print_array("A s_a", &ka_sa[32..64]);

            // kdf(z,1) to compute Kb || Sb
            let mut kb_sb = vec![0; 64];
            let mut input = z.clone();
            input.push(1);
            assert_eq!(sha2_512_hash(kb_sb.as_mut_slice(), input.as_slice()),
                       Ok(()));
            print_array("A k_b", &kb_sb[0..32]);
            print_array("A s_b", &kb_sb[32..64]);

            // kdf(z,2) to compute Kclient || Sclient
            let mut kc_sc = vec![0; 64];
            let mut input = z.clone();
            input.push(2);
            assert_eq!(sha2_512_hash(kc_sc.as_mut_slice(), input.as_slice()),
                       Ok(()));
            print_array("A k_c", &kc_sc[0..32]);
            print_array("A s_c", &kc_sc[32..64]);

            // 9. A decrypts the remainder of the message, verifies the signature.
            let mut plaintext = vec![0; 64];
            let aad = vec![];
            let mac = &message2[96..];
            let ciphertext = &message2[32..96];
            let s_b = &kb_sb[32..64];
            let nonce = &s_b[0..12];
            print_array("A mac", &mac);
            print_array("A cipheryext", &ciphertext);
            print_array("A s_b", &s_b);
            print_array("A nonce", &nonce);

            let success = match chacha20poly1305_aead_decrypt(plaintext.as_mut_slice(),
                                                              &mac,
                                                              &ciphertext,
                                                              &aad,
                                                              &kb_sb[0..32],
                                                              nonce) {
                Ok(val) => val,
                Err(msg) => panic!("Error! {}", msg),
            };

            assert_eq!(success, true);
            print_array("A decrypted sig", &plaintext);

            // 9. verifies the signature.
            let mut pbe_pae = p_be.clone();
            pbe_pae.append(&mut p_ae.clone());
            print_array("A pbe_pae", &pbe_pae);
            let success = match ed25519_verify(&p_b, &pbe_pae, &plaintext) {
                Ok(val) => val,
                Err(msg) => panic!("Error! {}", msg),
            };
            assert_eq!(success, true);
            println!("A signature verified: {}", success);



        }
    }



    fn thread_b(tx: mpsc::Sender<Vec<u8>>, rx: mpsc::Receiver<Vec<u8>>) {
        // B
//        // assymetric public key
//        let p_b = vec![0xE4, 0xD5, 0x17, 0x13, 0xEB, 0xF8, 0x82, 0xCC, 0x7A, 0x90, 0x29, 0x14,
//                       0x59, 0xCC, 0x84, 0x7E, 0xA2, 0xD3, 0xE9, 0x5E, 0x9E, 0x4, 0x26, 0x90,
//                       0x83, 0x44, 0xE9, 0x5B, 0xA, 0xB7, 0x14, 0x42];
        // assymetric secret key
        let q_b = vec![0x13, 0x4B, 0x63, 0x9E, 0x68, 0x0, 0x9C, 0x72, 0x8D, 0xB3, 0x64, 0xA0,
                       0xCD, 0xA3, 0xF3, 0x2F, 0xB5, 0x4D, 0x23, 0x8, 0x7F, 0x33, 0x2C, 0x79,
                       0x9F, 0xCD, 0x5F, 0x7D, 0x49, 0xA8, 0x25, 0xB5];
		let mut p_b = vec![0;32];
		ed25519_secret_to_public(p_b.as_mut_slice(), q_b.as_slice()).unwrap();
		print_array("A p_b", &p_b);

        // B
        // given secrect key, we dont generate anything
        let q_be = vec![0x5F, 0x47, 0x51, 0xFE, 0x56, 0xF2, 0x63, 0x5D, 0xC6, 0x79, 0x8D, 0x5,
                        0x4A, 0x9, 0x92, 0x70, 0x21, 0x2C, 0xB2, 0x79, 0x44, 0xD9, 0xF8, 0x26,
                        0xBB, 0xA, 0xAA, 0xB3, 0xFE, 0xCE, 0x88, 0x74];

        let mut status = StatusB::Uninit;

        loop {
            // basepoint
            let mut basepoint: [u8; 32] = [0; 32];
            basepoint[0] = 9;

            // 2. B generates ephemeral curve25519 key pair (Pbe, Qbe).
            let mut p_be = vec![0; 32];
            assert_eq!(curve25519_crypto_scalarmult(p_be.as_mut_slice(),
                                                    q_be.as_slice(),
                                                    &basepoint),
                       Ok(()));
            print_array("B p_be", &p_be);

            status = StatusB::WaitingForMessage1;

            let message1 = rx.recv().expect("Couldn't receive data");
            let p_ae = message1;

            // 3. B computes the shared secret: z = scalar_multiplication(Qbe, Pae)
            let mut z = vec![0; 32];
            assert_eq!(curve25519_crypto_scalarmult(z.as_mut_slice(),
                                                    q_be.as_slice(),
                                                    &p_ae.as_slice()),
                       Ok(()));
            print_array("B z", &z);

            // 4. B uses the key derivation function kdf(z,1) to compute Kb || Sb, kdf(z,0) to
            // compute Ka || Sa, and kdf(z,2) to compute Kclient || Sclient.
            // kdf(z,partyIdent) = SHA512( 0 || z || partyIdent)
            // (0 for A, 1 for B and 2 for key material returned to the callee)

            // kdf(z,0) to compute Ka || Sa
            let mut ka_sa = vec![0; 64];
            let mut input = z.clone();
            input.push(0);
            assert_eq!(sha2_512_hash(ka_sa.as_mut_slice(), input.as_slice()),
                       Ok(()));
            print_array("B k_a", &ka_sa[0..32]);
            print_array("B s_a", &ka_sa[32..64]);

            // kdf(z,1) to compute Kb || Sb
            let mut kb_sb = vec![0; 64];
            let mut input = z.clone();
            input.push(1);
            assert_eq!(sha2_512_hash(kb_sb.as_mut_slice(), input.as_slice()),
                       Ok(()));
            print_array("B k_b", &kb_sb[0..32]);
            print_array("B s_b", &kb_sb[32..64]);

            // kdf(z,2) to compute Kclient || Sclient
            let mut kc_sc = vec![0; 64];
            let mut input = z.clone();
            input.push(2);
            assert_eq!(sha2_512_hash(kc_sc.as_mut_slice(), input.as_slice()),
                       Ok(()));
            print_array("B k_c", &kc_sc[0..32]);
            print_array("B s_c", &kc_sc[32..64]);

            // 5. B computes the ed25519 signature: sig = signQb(Pbe || Pae)
            let mut sig = vec![0; 64];
            let mut pbe_pae = p_be.clone();
            pbe_pae.append(&mut p_ae.clone());
            print_array("B pbe_pae", &pbe_pae);

            assert_eq!(ed25519_sign(sig.as_mut_slice(), q_b.as_slice(), pbe_pae.as_slice()),
                       Ok(()));
            print_array("B sig", &sig);

            // 6. B computes and sends the message Pbe || Ekey=Kb,IV=Sb||zero(sig)
            let mut mac: Vec<u8> = vec![0; 16];
            let aad = vec![];
            let mut ciphertext: Vec<u8> = vec![0; 64];
            let s_b = &kb_sb[32..64];
            let nonce = &s_b[0..12];


            let success = match chacha20poly1305_aead_encrypt(ciphertext.as_mut_slice(),
                                                              mac.as_mut_slice(),
                                                              &sig,
                                                              &aad,
                                                              &kb_sb[0..32],
                                                              nonce) {
                Ok(val) => val,
                Err(msg) => panic!("Error! {}", msg),
            };
            assert_eq!(success, true);
            print_array("B ciphertext", &ciphertext);
            print_array("B mac", &mac);
            print_array("B nonce", &nonce);

            let mut message2 = p_be.clone();
            print_array("B p_be", &message2);
            message2.append(&mut ciphertext);
            message2.append(&mut mac);

            status = StatusB::SendMessage2;
            tx.send(message2).expect("B Couldn't send data");

            status = StatusB::WaitingForMEssage3;
            let message3 = rx.recv().expect(" Couldn't receive data");

        }
    }

    #[test]
    fn test_gec() {

        // channels setup
        let (tx_a, rx_a) = mpsc::channel();
        let (tx_b, rx_b) = mpsc::channel();


        println!("GEC starting.");

        let th_a = thread::spawn(move || thread_a(tx_a, rx_b));
        let th_b = thread::spawn(move || thread_b(tx_b, rx_a));
        th_a.join().expect("Thread A error");
        th_b.join().expect("Thread B error");
    }



}
