use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::StreamConfig;

const STREAM_METADATA_VERSION: u32 = 1;

/// Wrapper for versioned serialization of StreamConfig
#[derive(Serialize, Deserialize)]
struct VersionedStreamConfig {
    version: u32,
    config: StreamConfig,
}

/// Serialize a StreamConfig into binary format for storage in a slab
pub fn serialize_stream_config(cfg: &StreamConfig) -> Result<Vec<u8>> {
    let versioned = VersionedStreamConfig {
        version: STREAM_METADATA_VERSION,
        config: cfg.clone(),
    };
    bincode::serialize(&versioned).context("Failed to serialize stream config")
}

/// Deserialize a StreamConfig from binary format
pub fn deserialize_stream_config(data: &[u8]) -> Result<StreamConfig> {
    let versioned: VersionedStreamConfig =
        bincode::deserialize(data).context("Failed to deserialize stream config")?;

    if versioned.version != STREAM_METADATA_VERSION {
        return Err(anyhow!(
            "Unsupported stream metadata version: {} (expected {})",
            versioned.version,
            STREAM_METADATA_VERSION
        ));
    }

    Ok(versioned.config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() -> Result<()> {
        let original = StreamConfig {
            name: Some("test_stream".to_string()),
            source_path: "/dev/test".to_string(),
            pack_time: "2025-10-30T12:00:00+00:00".to_string(),
            size: 1024 * 1024 * 1024,
            mapped_size: 512 * 1024 * 1024,
            packed_size: 256 * 1024 * 1024,
            thin_id: Some(42),
            source_sig: Some("abc123".to_string()),
            first_mapping_slab: 10,
            num_mapping_slabs: 5,
        };

        let serialized = serialize_stream_config(&original)?;
        let deserialized = deserialize_stream_config(&serialized)?;

        assert_eq!(original, deserialized);

        Ok(())
    }

    #[test]
    fn test_optional_fields() -> Result<()> {
        let original = StreamConfig {
            name: None,
            source_path: "/dev/test".to_string(),
            pack_time: "2025-10-30T12:00:00+00:00".to_string(),
            size: 1024,
            mapped_size: 512,
            packed_size: 256,
            thin_id: None,
            source_sig: None,
            first_mapping_slab: 0,
            num_mapping_slabs: 1,
        };

        let serialized = serialize_stream_config(&original)?;
        let deserialized = deserialize_stream_config(&serialized)?;

        assert_eq!(original, deserialized);

        Ok(())
    }

    #[test]
    fn test_version_check() {
        // Create invalid data with wrong version
        let bad_versioned = VersionedStreamConfig {
            version: 999,
            config: StreamConfig {
                name: None,
                source_path: "/dev/test".to_string(),
                pack_time: "2025-10-30T12:00:00+00:00".to_string(),
                size: 1024,
                mapped_size: 512,
                packed_size: 256,
                thin_id: None,
                source_sig: None,
                first_mapping_slab: 0,
                num_mapping_slabs: 1,
            },
        };

        let bad_data = bincode::serialize(&bad_versioned).unwrap();
        let result = deserialize_stream_config(&bad_data);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }
}
