use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type ExtensionObject = BTreeMap<String, Value>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    #[serde(rename = "source_KME_ID")]
    pub source_kme_id: String,
    #[serde(rename = "target_KME_ID")]
    pub target_kme_id: String,
    #[serde(rename = "master_SAE_ID")]
    pub master_sae_id: String,
    #[serde(rename = "slave_SAE_ID")]
    pub slave_sae_id: String,
    pub key_size: i32,
    pub stored_key_count: i32,
    pub max_key_count: i32,
    pub max_key_per_request: i32,
    pub max_key_size: i32,
    pub min_key_size: i32,
    #[serde(rename = "max_SAE_ID_count")]
    pub max_sae_id_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_extension: Option<ExtensionObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i32>,
    #[serde(
        rename = "additional_slave_SAE_IDs",
        skip_serializing_if = "Option::is_none"
    )]
    pub additional_slave_sae_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_mandatory: Option<Vec<ExtensionObject>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_optional: Option<Vec<ExtensionObject>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyContainer {
    pub keys: Vec<KeyItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_container_extension: Option<ExtensionObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyItem {
    #[serde(rename = "key_ID")]
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id_extension: Option<ExtensionObject>,
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_extension: Option<ExtensionObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyIDs {
    #[serde(rename = "key_IDs")]
    pub key_ids: Vec<KeyIdItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ids_extension: Option<ExtensionObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyIdItem {
    #[serde(rename = "key_ID")]
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id_extension: Option<ExtensionObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<ExtensionObject>>,
}
