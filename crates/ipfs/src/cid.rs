//! Content identifiers (https://github.com/multiformats/cid) and multihashes
//! (https://github.com/multiformats/multihash).
//!
//! ```text
//! CIDv1 = <multibase-prefix><multibase( varint(1) || varint(codec) || multihash )>
//! multihash = varint(hash-code) || varint(digest-len) || digest
//! CIDv0 = base58btc( 0x12 0x20 || sha2-256 digest )      (implicitly dag-pb, "Qm...")
//! ```
//!
//! Parsing is strict: canonical varints, canonical multibase, exact digest lengths for
//! known hash functions, and CIDv0 only for dag-pb + sha2-256. A structurally valid CID
//! says nothing about the content; use [`Cid::verify`] against the actual bytes.

use crate::error::IpfsError;
use crate::{multibase, varint};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Multicodec codes (https://github.com/multiformats/multicodec/blob/master/table.csv).
pub mod codec {
    pub const RAW: u64 = 0x55;
    pub const DAG_PB: u64 = 0x70;
    pub const DAG_CBOR: u64 = 0x71;
    pub const DAG_JSON: u64 = 0x0129;

    /// Multicodec name, as accepted by Kubo's `--cid-codec`.
    pub fn name(code: u64) -> Option<&'static str> {
        match code {
            RAW => Some("raw"),
            DAG_PB => Some("dag-pb"),
            DAG_CBOR => Some("dag-cbor"),
            DAG_JSON => Some("dag-json"),
            _ => None,
        }
    }
}

/// Multihash function codes.
pub mod hash {
    pub const IDENTITY: u64 = 0x00;
    pub const SHA2_256: u64 = 0x12;
    pub const SHA2_512: u64 = 0x13;
    pub const BLAKE3: u64 = 0x1e;
}

/// Upper bound on digest length accepted by the parser (identity hashes included).
pub const MAX_DIGEST_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Multihash {
    code: u64,
    digest: Vec<u8>,
}

impl Multihash {
    pub fn new(code: u64, digest: Vec<u8>) -> Result<Self, IpfsError> {
        if digest.len() > MAX_DIGEST_LEN {
            return Err(IpfsError::InvalidCid(format!(
                "digest of {} B exceeds {MAX_DIGEST_LEN} B",
                digest.len()
            )));
        }
        let expected = match code {
            hash::SHA2_256 | hash::BLAKE3 => Some(32),
            hash::SHA2_512 => Some(64),
            _ => None,
        };
        if let Some(expected) = expected
            && digest.len() != expected
        {
            return Err(IpfsError::InvalidCid(format!(
                "multihash 0x{code:x} requires a {expected}-byte digest, got {}",
                digest.len()
            )));
        }
        Ok(Self { code, digest })
    }

    pub fn sha2_256(data: &[u8]) -> Self {
        Self {
            code: hash::SHA2_256,
            digest: Sha256::digest(data).to_vec(),
        }
    }

    pub fn code(&self) -> u64 {
        self.code
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Whether `data` hashes to this multihash. Errors for hash functions this crate
    /// cannot compute, so an unverifiable block is never reported as valid.
    pub fn matches(&self, data: &[u8]) -> Result<bool, IpfsError> {
        match self.code {
            hash::SHA2_256 => Ok(Sha256::digest(data).as_slice() == self.digest.as_slice()),
            hash::IDENTITY => Ok(data == self.digest.as_slice()),
            other => Err(IpfsError::UnsupportedHash(other)),
        }
    }

    fn write_bytes(&self, out: &mut Vec<u8>) {
        varint::encode(self.code, out);
        varint::encode(self.digest.len() as u64, out);
        out.extend_from_slice(&self.digest);
    }

    fn read_bytes(data: &[u8]) -> Result<(Self, usize), IpfsError> {
        let (code, a) = varint::decode(data)?;
        let (len, b) = varint::decode(&data[a..])?;
        let start = a + b;
        let len = usize::try_from(len)
            .ok()
            .filter(|&l| l <= MAX_DIGEST_LEN)
            .ok_or_else(|| IpfsError::InvalidCid("digest length too large".into()))?;
        let digest = data
            .get(start..start + len)
            .ok_or_else(|| IpfsError::InvalidCid("truncated multihash digest".into()))?;
        Ok((Self::new(code, digest.to_vec())?, start + len))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CidVersion {
    V0,
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid {
    version: CidVersion,
    codec: u64,
    hash: Multihash,
}

impl Cid {
    pub fn new_v1(codec: u64, hash: Multihash) -> Self {
        Self {
            version: CidVersion::V1,
            codec,
            hash,
        }
    }

    pub fn new_v0(hash: Multihash) -> Result<Self, IpfsError> {
        if hash.code != hash::SHA2_256 {
            return Err(IpfsError::InvalidCid("CIDv0 requires sha2-256".into()));
        }
        Ok(Self {
            version: CidVersion::V0,
            codec: codec::DAG_PB,
            hash,
        })
    }

    /// CIDv1 of `data` with `codec` and sha2-256 (the IPFS default hash).
    pub fn sha2_256(codec: u64, data: &[u8]) -> Self {
        Self::new_v1(codec, Multihash::sha2_256(data))
    }

    pub fn version(&self) -> CidVersion {
        self.version
    }

    pub fn codec(&self) -> u64 {
        self.codec
    }

    pub fn hash(&self) -> &Multihash {
        &self.hash
    }

    /// Equivalent CIDv1 (identity for v1).
    pub fn to_v1(&self) -> Self {
        Self::new_v1(self.codec, self.hash.clone())
    }

    /// Binary form (CIDv0: bare multihash).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.hash.digest.len());
        if self.version == CidVersion::V1 {
            varint::encode(1, &mut out);
            varint::encode(self.codec, &mut out);
        }
        self.hash.write_bytes(&mut out);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, IpfsError> {
        if data.len() == 34 && data[0] == 0x12 && data[1] == 0x20 {
            let (hash, _) = Multihash::read_bytes(data)?;
            return Self::new_v0(hash);
        }
        let (version, a) = varint::decode(data)?;
        match version {
            1 => {}
            0x12 => return Err(IpfsError::InvalidCid("malformed CIDv0".into())),
            v => {
                return Err(IpfsError::InvalidCid(format!(
                    "unsupported CID version {v}"
                )));
            }
        }
        let (codec, b) = varint::decode(&data[a..])?;
        let (hash, c) = Multihash::read_bytes(&data[a + b..])?;
        if a + b + c != data.len() {
            return Err(IpfsError::InvalidCid(
                "trailing bytes after multihash".into(),
            ));
        }
        Ok(Self::new_v1(codec, hash))
    }

    /// Check `data` against this CID's multihash.
    pub fn verify(&self, data: &[u8]) -> Result<(), IpfsError> {
        if self.hash.matches(data)? {
            Ok(())
        } else {
            Err(IpfsError::DigestMismatch { cid: self.clone() })
        }
    }
}

impl fmt::Display for Cid {
    /// CIDv1: base32 lowercase with prefix `b` (IPFS default). CIDv0: base58btc.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.version {
            CidVersion::V0 => f.write_str(&multibase::base58_encode(&self.to_bytes())),
            CidVersion::V1 => write!(f, "b{}", multibase::base32_encode(&self.to_bytes())),
        }
    }
}

impl FromStr for Cid {
    type Err = IpfsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 46 && s.starts_with("Qm") {
            let cid = Self::from_bytes(&multibase::base58_decode(s)?)?;
            if cid.version != CidVersion::V0 {
                return Err(IpfsError::InvalidCid("malformed CIDv0".into()));
            }
            return Ok(cid);
        }
        let mut chars = s.chars();
        let bytes = match chars.next() {
            Some('b') if !s[1..].bytes().any(|c| c.is_ascii_uppercase()) => {
                multibase::base32_decode(chars.as_str())?
            }
            Some('B') if !s[1..].bytes().any(|c| c.is_ascii_lowercase()) => {
                multibase::base32_decode(chars.as_str())?
            }
            Some('z') => multibase::base58_decode(chars.as_str())?,
            Some(p) => {
                return Err(IpfsError::InvalidCid(format!(
                    "unsupported or invalid multibase prefix {p:?}"
                )));
            }
            None => return Err(IpfsError::InvalidCid("empty string".into())),
        };
        let cid = Self::from_bytes(&bytes)?;
        if cid.version == CidVersion::V0 {
            return Err(IpfsError::InvalidCid(
                "CIDv0 must not carry a multibase prefix".into(),
            ));
        }
        Ok(cid)
    }
}

impl Serialize for Cid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independently computed with Python hashlib + base64 (see crate tests).
    const EMPTY_RAW: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    const HELLO_RAW: &str = "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e";
    const HELLO_DAG_PB_V1: &str = "bafybeifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e";
    const HELLO_V0: &str = "QmaozNR7DZHQK1ZcU9p7QdrshMvXqWK6gpu5rmrkPdT3L4";
    const HELLO_DAG_JSON: &str = "baguqeeraxfgspomtju7arjjokll5u7nl7lcij37dpjjyb3uqrd32zyxpzxuq";

    #[test]
    fn computes_reference_cids() {
        assert_eq!(Cid::sha2_256(codec::RAW, b"").to_string(), EMPTY_RAW);
        assert_eq!(
            Cid::sha2_256(codec::RAW, b"hello world").to_string(),
            HELLO_RAW
        );
        assert_eq!(
            Cid::sha2_256(codec::DAG_JSON, b"hello world").to_string(),
            HELLO_DAG_JSON
        );
        let v0 = Cid::new_v0(Multihash::sha2_256(b"hello world")).unwrap();
        assert_eq!(v0.to_string(), HELLO_V0);
        assert_eq!(v0.to_v1().to_string(), HELLO_DAG_PB_V1);
    }

    #[test]
    fn parse_roundtrip_all_forms() {
        for s in [
            EMPTY_RAW,
            HELLO_RAW,
            HELLO_DAG_PB_V1,
            HELLO_V0,
            HELLO_DAG_JSON,
        ] {
            let cid: Cid = s.parse().unwrap();
            assert_eq!(cid.to_string(), s);
            assert_eq!(Cid::from_bytes(&cid.to_bytes()).unwrap(), cid);
        }
        let upper: Cid = HELLO_RAW.to_ascii_uppercase().parse().unwrap();
        assert_eq!(upper.to_string(), HELLO_RAW);
        let z = format!("z{}", multibase::base58_encode(&upper.to_bytes()));
        assert_eq!(z.parse::<Cid>().unwrap(), upper);
        let v0: Cid = HELLO_V0.parse().unwrap();
        assert_eq!(v0.version(), CidVersion::V0);
        assert_eq!(v0.codec(), codec::DAG_PB);
    }

    #[test]
    fn rejects_invalid_cids() {
        for bad in [
            "",
            "b",
            // Legacy mock output: contains 0/1/8/9, which are not base32.
            "bafybeigf7b969b0912a860600000073",
            &HELLO_RAW[..HELLO_RAW.len() - 1],
            &format!("{HELLO_RAW}a"),
            &format!("m{}", &HELLO_RAW[1..]),
            "bafkreifzjuT3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e",
            &format!("z{HELLO_V0}"),
            &HELLO_V0[..45],
        ] {
            assert!(bad.parse::<Cid>().is_err(), "accepted {bad:?}");
        }
        // Wrong digest length for sha2-256.
        let mut bytes = vec![1, 0x55, 0x12, 0x1f];
        bytes.extend([0u8; 31]);
        assert!(Cid::from_bytes(&bytes).is_err());
        // Unsupported CID version.
        assert!(Cid::from_bytes(&[2, 0x55, 0x00, 0x00]).is_err());
        // Non-minimal varint codec.
        let mut bytes = vec![1, 0xd5, 0x00, 0x12, 0x20];
        bytes.extend([0u8; 32]);
        assert!(Cid::from_bytes(&bytes).is_err());
    }

    #[test]
    fn verify_detects_tampering() {
        let cid = Cid::sha2_256(codec::RAW, b"hello world");
        assert!(cid.verify(b"hello world").is_ok());
        assert!(matches!(
            cid.verify(b"hello worle"),
            Err(IpfsError::DigestMismatch { .. })
        ));
        let blake = Cid::new_v1(
            codec::RAW,
            Multihash::new(hash::BLAKE3, vec![0; 32]).unwrap(),
        );
        assert_eq!(
            blake.verify(b"x"),
            Err(IpfsError::UnsupportedHash(hash::BLAKE3))
        );
    }

    #[test]
    fn serde_uses_string_form() {
        let cid: Cid = HELLO_RAW.parse().unwrap();
        let json = serde_json::to_string(&cid).unwrap();
        assert_eq!(json, format!("\"{HELLO_RAW}\""));
        assert_eq!(serde_json::from_str::<Cid>(&json).unwrap(), cid);
        assert!(serde_json::from_str::<Cid>("\"bafybeigf7b969b0912a860600000073\"").is_err());
    }
}
