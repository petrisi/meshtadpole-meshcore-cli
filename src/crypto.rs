//! MeshCore cryptography: Ed25519 identities (64-byte expanded private keys as in orlp/ed25519),
//! X25519 shared secrets from Ed25519 keys, AES-128-ECB with 2-byte HMAC-SHA256 MAC.

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use anyhow::{Result, anyhow, bail};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub const PUB_KEY_SIZE: usize = 32;
pub const PRV_KEY_SIZE: usize = 64;
pub const MAC_SIZE: usize = 2;
pub const BLOCK: usize = 16;

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Local identity: 64-byte expanded private key (clamped scalar || nonce prefix) and public key.
#[derive(Clone)]
pub struct Identity {
    pub prv: [u8; PRV_KEY_SIZE],
    pub public: [u8; PUB_KEY_SIZE],
}

impl Identity {
    /// New random key pair (orlp ed25519_create_keypair: sha512(seed), clamp). Public keys with first byte
    /// 0x00 or 0xFF are reserved by the firmware and skipped.
    pub fn generate() -> Identity {
        loop {
            let seed: [u8; 32] = rand::random();
            let id = Identity::from_seed(&seed);
            if id.public[0] != 0x00 && id.public[0] != 0xFF {
                return id;
            }
        }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Identity {
        let mut prv: [u8; 64] = Sha512::digest(seed).into();
        prv[0] &= 248;
        prv[31] &= 63;
        prv[31] |= 64;
        Identity::from_private(&prv).expect("valid")
    }

    /// From a 64-byte expanded private key; public key derived.
    pub fn from_private(prv: &[u8]) -> Result<Identity> {
        let prv: [u8; 64] = prv.try_into().map_err(|_| anyhow!("private key must be 64 bytes"))?;
        let mut lower = [0u8; 32];
        lower.copy_from_slice(&prv[..32]);
        let s = Scalar::from_bytes_mod_order(clamp_integer(lower));
        let public = curve25519_dalek::EdwardsPoint::mul_base(&s).compress().to_bytes();
        Ok(Identity { prv, public })
    }

    pub fn from_hex(h: &str) -> Result<Identity> {
        let b = hex::decode(h.trim()).map_err(|e| anyhow!("private key hex: {e}"))?;
        Identity::from_private(&b)
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }

    /// Ed25519 signature with the expanded key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let esk = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&self.prv);
        let vk = VerifyingKey::from_bytes(&self.public).expect("own public key");
        ed25519_dalek::hazmat::raw_sign::<Sha512>(&esk, msg, &vk).to_bytes()
    }

    /// Shared secret with a peer (orlp ed25519_key_exchange): X25519 of our clamped scalar and the
    /// peer's Ed25519 key converted to Montgomery form. Raw, not hashed.
    pub fn shared_secret(&self, peer_public: &[u8; 32]) -> Result<[u8; 32]> {
        let ed = CompressedEdwardsY(*peer_public).decompress().ok_or_else(|| anyhow!("invalid peer public key"))?;
        let mut k = [0u8; 32];
        k.copy_from_slice(&self.prv[..32]);
        Ok(ed.to_montgomery().mul_clamped(k).to_bytes())
    }
}

/// Verify an Ed25519 signature.
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public) else { return false };
    let Ok(sig) = Signature::from_slice(sig) else { return false };
    vk.verify_strict(msg, &sig).is_ok() || ed25519_dalek::Verifier::verify(&vk, msg, &sig).is_ok()
}

/// 2-byte MAC: HMAC-SHA256 keyed with the full 32-byte secret, over the ciphertext.
fn mac(secret: &[u8; 32], ct: &[u8]) -> [u8; 2] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).unwrap();
    m.update(ct);
    let r = m.finalize().into_bytes();
    [r[0], r[1]]
}

/// MAC check then AES-128-ECB decrypt (key = secret[0..16]). Input: MAC(2) || ciphertext. Output is zero-padded.
pub fn mac_then_decrypt(secret: &[u8; 32], src: &[u8]) -> Option<Vec<u8>> {
    if src.len() <= MAC_SIZE {
        return None;
    }
    let ct = &src[MAC_SIZE..];
    if ct.len() % BLOCK != 0 || mac(secret, ct) != src[..MAC_SIZE] {
        return None;
    }
    let c = Aes128::new(GenericArray::from_slice(&secret[..16]));
    let mut out = ct.to_vec();
    for b in out.chunks_mut(BLOCK) {
        c.decrypt_block(GenericArray::from_mut_slice(b));
    }
    Some(out)
}

/// AES-128-ECB encrypt (zero padding) then MAC. Output: MAC(2) || ciphertext.
pub fn encrypt_then_mac(secret: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let c = Aes128::new(GenericArray::from_slice(&secret[..16]));
    let mut ct = plain.to_vec();
    ct.resize(plain.len().div_ceil(BLOCK).max(1) * BLOCK, 0);
    for b in ct.chunks_mut(BLOCK) {
        c.encrypt_block(GenericArray::from_mut_slice(b));
    }
    let mut out = mac(secret, &ct).to_vec();
    out.extend(ct);
    out
}

/// Group channel secret (key zero-extended to 32 bytes) and hash byte (sha256(key)[0]).
pub fn channel_secret(key: &[u8]) -> Result<([u8; 32], u8)> {
    if key.len() != 16 && key.len() != 32 {
        bail!("channel key must be 16 or 32 bytes, got {}", key.len());
    }
    let mut s = [0u8; 32];
    s[..key.len()].copy_from_slice(key);
    Ok((s, sha256(&[key])[0]))
}

/// Hashtag channel key: sha256("#name")[0..16].
pub fn hashtag_key(name: &str) -> [u8; 16] {
    let h = sha256(&[name.as_bytes()]);
    let mut k = [0u8; 16];
    k.copy_from_slice(&h[..16]);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public test client key pair from MeshCore firmware (Identity.cpp validatePrivateKey).
    const TEST_PRV: &str =
        "7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471";
    const TEST_PUB: &str = "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10";

    #[test]
    fn derive_public() {
        let id = Identity::from_hex(TEST_PRV).unwrap();
        assert_eq!(id.public_hex(), TEST_PUB);
    }

    #[test]
    fn shared_secret_symmetric() {
        let a = Identity::from_hex(TEST_PRV).unwrap();
        let b = Identity::generate();
        assert_eq!(a.shared_secret(&b.public).unwrap(), b.shared_secret(&a.public).unwrap());
    }

    #[test]
    fn sign_verify() {
        let a = Identity::generate();
        let s = a.sign(b"hello");
        assert!(verify(&a.public, b"hello", &s));
        assert!(!verify(&a.public, b"hellp", &s));
    }

    #[test]
    fn channel_keys() {
        assert_eq!(hex::encode(hashtag_key("#test")), "9cd8fcf22a47333b591d96a2b848b73f");
        let (s, _) = channel_secret(&hashtag_key("#test")).unwrap();
        let ct = encrypt_then_mac(&s, b"abc");
        assert_eq!(ct.len(), 2 + 16);
        let pt = mac_then_decrypt(&s, &ct).unwrap();
        assert_eq!(&pt[..3], b"abc");
    }
}
