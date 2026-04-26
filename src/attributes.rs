use std::collections::HashMap;

use aes::Aes128;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use json::Value;
use serde::{Deserialize, Serialize};

use crate::fingerprint::NodeFingerprint;
use crate::{Result, error};

/// Represents the node's attributes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct NodeAttributes {
    /// The name of the node.
    #[serde(rename = "n")]
    pub name: String,
    /// The encoded fingerprint for the node.
    #[serde(rename = "c", skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// The last modified date of the node.
    #[serde(rename = "t", skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<i64>,
    /// Catch-all for the remaining fields (if any).
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

impl NodeAttributes {
    pub(crate) fn decrypt_and_unpack(file_key: &[u8; 16], buffer: &mut [u8]) -> Result<Self> {
        use cipher::generic_array::GenericArray;
        use cipher::{BlockDecryptMut, KeyInit};

        // 1. AES block size is 16. Ensure buffer is valid.
        if buffer.len() % 16 != 0 {
            return Err(error::Error::InvalidResponseType);
        }

        // 2. Initialize the decryptor
        let mut cbc = cbc::Decryptor::<Aes128>::new(file_key.into(), &<_>::default());

        // 3. Cast the buffer slice to a slice of GenericArrays (Blocks)
        // This safely reinterprets the &mut [u8] as &mut [GenericArray<u8, U16>]
        let blocks = unsafe {
            let (prefix, blocks, suffix) =
                buffer.align_to_mut::<GenericArray<u8, cipher::consts::U16>>();
            if !prefix.is_empty() || !suffix.is_empty() {
                return Err(error::Error::InvalidResponseType);
            }
            blocks
        };

        // 4. Decrypt all blocks in one go to maintain CBC chaining
        cbc.decrypt_blocks_mut(blocks);

        // 5. Validation and Parsing
        if &buffer[..4] != b"MEGA" {
            println!(
                "DECRYPTION FAILED. First 8 bytes (hex): {:02x?}",
                &buffer[..8]
            );
            println!("Used Key (hex): {:02x?}", file_key);
            return Err(error::Error::InvalidResponseType);
        }

        let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        let attrs = json::from_slice(&buffer[4..len])?;

        Ok(attrs)
    }
    pub(crate) fn pack_and_encrypt(&self, file_key: &[u8; 16]) -> Result<Vec<u8>> {
        let mut buffer = b"MEGA".to_vec();
        json::to_writer(&mut buffer, self)?;

        let padding_len = (16 - buffer.len() % 16) % 16;
        buffer.extend(std::iter::repeat(b'\0').take(padding_len));

        let mut cbc = cbc::Encryptor::<Aes128>::new(file_key.into(), &<_>::default());
        for chunk in buffer.chunks_exact_mut(16) {
            cbc.encrypt_block_mut(chunk.into());
        }

        Ok(buffer)
    }

    pub(crate) fn extract_fingerprint(&self) -> Option<NodeFingerprint> {
        let checksum = self.fingerprint.as_deref()?;
        NodeFingerprint::deserialize(checksum)
    }
}
