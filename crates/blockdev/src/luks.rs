//! Parsing for `cryptsetup luksDump --dump-json-metadata` output.

use std::collections::BTreeMap;

use anyhow::Context;
use bootc_utils::CommandRunExt;
use serde::Deserialize;

/// Top-level LUKS2 metadata as emitted by
/// `cryptsetup luksDump --dump-json-metadata <device>`.
#[derive(Debug, Clone, Deserialize)]
pub struct LuksMetadata {
    /// Keyslots, keyed by slot number (as a string, e.g. `"0"`). Each holds an
    /// encrypted copy of a volume key protected by a passphrase or token.
    pub keyslots: BTreeMap<String, Keyslot>,
    /// Tokens, keyed by token number. A token describes how a keyslot can be
    /// unlocked by something other than a passphrase (e.g. a TPM2 or FIDO2
    /// device). The shape is token-type specific, so this is left as raw JSON.
    pub tokens: BTreeMap<String, serde_json::Value>,
    /// Data segments, keyed by segment number. A segment maps a region of the
    /// device to an encryption configuration.
    pub segments: BTreeMap<String, Segment>,
    /// Digests, keyed by digest number. A digest verifies that a decrypted
    /// volume key is correct and binds keyslots to segments.
    pub digests: BTreeMap<String, Digest>,
    /// Global configuration of the metadata area.
    pub config: Config,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Keyslot {
    /// Keyslot type, e.g. `"luks2"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Size of the stored volume key, in bytes.
    pub key_size: u32,
    /// Anti-forensic splitter configuration for the stored key material.
    pub af: Af,
    /// Location on disk where the (AF-split) encrypted key material is stored.
    pub area: Area,
    /// Key derivation function used to turn the passphrase into a key.
    pub kdf: Kdf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Af {
    /// Anti-forensic splitter type, e.g. `"luks1"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Number of stripes the key material is split into.
    pub stripes: u32,
    /// Hash algorithm used by the splitter, e.g. `"sha256"`.
    pub hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Area {
    /// Storage type for the key material area, e.g. `"raw"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Byte offset of the area within the device (string-encoded integer).
    pub offset: String,
    /// Size of the area in bytes (string-encoded integer).
    pub size: String,
    /// Cipher used to encrypt the key material, e.g. `"aes-xts-plain64"`.
    pub encryption: String,
    /// Key size of the area encryption cipher, in bytes.
    pub key_size: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Kdf {
    /// KDF type, e.g. `"argon2id"` or `"pbkdf2"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Argon2 time cost (iterations). Present for Argon2 KDFs.
    pub time: Option<u32>,
    /// Argon2 memory cost in KiB. Present for Argon2 KDFs.
    pub memory: Option<u32>,
    /// Argon2 parallelism (number of threads). Present for Argon2 KDFs.
    pub cpus: Option<u32>,
    /// Base64-encoded salt fed into the KDF.
    pub salt: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Segment {
    /// Segment type, e.g. `"crypt"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Byte offset of the segment on the device (string-encoded integer).
    pub offset: String,
    /// Segment size: a byte count (string-encoded integer) or the literal
    /// `"dynamic"`, meaning it extends to the end of the device.
    pub size: String,
    /// Initialization vector tweak / sector offset (string-encoded integer).
    pub iv_tweak: String,
    /// Cipher used for this segment, e.g. `"aes-xts-plain64"`.
    pub encryption: String,
    /// Encryption sector size in bytes, e.g. `512`.
    pub sector_size: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Digest {
    /// Digest type, e.g. `"pbkdf2"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Keyslot numbers (as strings) this digest applies to.
    pub keyslots: Vec<String>,
    /// Segment numbers (as strings) this digest applies to.
    pub segments: Vec<String>,
    /// Hash algorithm used for the digest, e.g. `"sha256"`.
    pub hash: String,
    /// Iteration count used when computing the digest.
    pub iterations: u32,
    /// Base64-encoded salt used when computing the digest.
    pub salt: String,
    /// Base64-encoded digest of the volume key.
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Size of the JSON metadata area in bytes (string-encoded integer).
    pub json_size: String,
    /// Size of the binary keyslots area in bytes (string-encoded integer).
    pub keyslots_size: String,
    /// Global LUKS2 flags, e.g. `"allow-discards"`. May be absent.
    #[serde(default)]
    pub flags: Vec<String>,
}

impl LuksMetadata {
    /// Parse the JSON output of
    /// `cryptsetup luksDump --dump-json-metadata <device>`.
    pub fn from_json(data: &str) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(data)?)
    }

    pub fn query_json(device: &str) -> anyhow::Result<Self> {
        let out = std::process::Command::new("cryptsetup")
            .args(["luksDump", "--dump-json-metadata", device])
            .run_get_string()
            .with_context(|| format!("Querying LUKS metdata for {device}"))?;

        Self::from_json(&out)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const EXAMPLE: &str = r#"
{
  "keyslots":{
    "0":{
      "type":"luks2",
      "key_size":64,
      "af":{
        "type":"luks1",
        "stripes":4000,
        "hash":"sha512"
      },
      "area":{
        "type":"raw",
        "offset":"32768",
        "size":"258048",
        "encryption":"aes-xts-plain64",
        "key_size":64
      },
      "kdf":{
        "type":"pbkdf2",
        "hash":"sha512",
        "iterations":1000,
        "salt":"B5XGJUBkEFoeVJ7lrLwWpK2XMOAmm6hj4th73CUB9mc="
      }
    }
  },
  "tokens":{
    "0":{
      "type":"systemd-tpm2",
      "keyslots":[
        "0"
      ],
      "tpm2-blob":"AJ4AIJRnkoe884vz6T6pNfSNIs5ryQcS+fdbJjLD9Cp80b86ABALaOT0DjTUhzro6vYNK8",
      "tpm2-pcrs":[],
      "tpm2-policy-hash":"0000000000000000000000000000000000000000000000000000000000000000",
      "tpm2_srk":"gQAAAQAiAAuof4FTaepKUYJv99SfGWTUyGhU9wFDdgBDJ5CD+h7sawAAAAEAWgAjAAsAAwR"
    }
  },
  "segments":{
    "0":{
      "type":"crypt",
      "offset":"16777216",
      "size":"dynamic",
      "iv_tweak":"0",
      "encryption":"aes-xts-plain64",
      "sector_size":512
    }
  },
  "digests":{
    "0":{
      "type":"pbkdf2",
      "keyslots":[
        "0"
      ],
      "segments":[
        "0"
      ],
      "hash":"sha256",
      "iterations":608929,
      "salt":"WQVLdC7ihl1kN5pnXh1N6H5OKVYnt5WjeB0J0Manp6A=",
      "digest":"BNTDijAmv1jqBl4O1gjLMZxk1VOi3Iw0lLi2hyDuboc="
    }
  },
  "config":{
    "json_size":"12288",
    "keyslots_size":"16744448"
  }
}
"#;

    #[test]
    fn test_parse() {
        let md = LuksMetadata::from_json(EXAMPLE).unwrap();
        assert_eq!(md.keyslots.len(), 1);
        assert_eq!(md.keyslots["0"].kind, "luks2");
        assert_eq!(md.keyslots["0"].key_size, 64);
        assert_eq!(md.keyslots["0"].kdf.kind, "pbkdf2");
        // pbkdf2 has no argon2 time/memory/cpus fields
        assert_eq!(md.keyslots["0"].kdf.time, None);
        assert_eq!(md.keyslots["0"].area.offset, "32768");

        // A single systemd-tpm2 token bound to keyslot 0
        assert_eq!(md.tokens.len(), 1);
        assert_eq!(
            md.tokens["0"].get("type").and_then(|v| v.as_str()),
            Some("systemd-tpm2")
        );

        assert_eq!(md.segments["0"].size, "dynamic");
        assert_eq!(md.digests["0"].keyslots, vec!["0"]);
        // This dump has no config flags
        assert!(md.config.flags.is_empty());
    }
}
