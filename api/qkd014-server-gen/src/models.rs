#![allow(unused_qualifications)]

use http::HeaderValue;
use validator::Validate;

#[cfg(feature = "server")]
use crate::header;
use crate::{models, types::*};

#[allow(dead_code)]
fn from_validation_error(e: validator::ValidationError) -> validator::ValidationErrors {
  let mut errs = validator::ValidationErrors::new();
  errs.add("na", e);
  errs
}

#[allow(dead_code)]
pub fn check_xss_string(v: &str) -> std::result::Result<(), validator::ValidationError> {
    if ammonia::is_html(v) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}

#[allow(dead_code)]
pub fn check_xss_vec_string(v: &[String]) -> std::result::Result<(), validator::ValidationError> {
    if v.iter().any(|i| ammonia::is_html(i)) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}

#[allow(dead_code)]
pub fn check_xss_map_string(
    v: &std::collections::HashMap<String, String>,
) -> std::result::Result<(), validator::ValidationError> {
    if v.keys().any(|k| ammonia::is_html(k)) || v.values().any(|v| ammonia::is_html(v)) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}

#[allow(dead_code)]
pub fn check_xss_map_nested<T>(
    v: &std::collections::HashMap<String, T>,
) -> std::result::Result<(), validator::ValidationError>
where
    T: validator::Validate,
{
    if v.keys().any(|k| ammonia::is_html(k)) || v.values().any(|v| v.validate().is_err()) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}

#[allow(dead_code)]
pub fn check_xss_map<T>(v: &std::collections::HashMap<String, T>) -> std::result::Result<(), validator::ValidationError> {
    if v.keys().any(|k| ammonia::is_html(k)) {
        std::result::Result::Err(validator::ValidationError::new("xss detected"))
    } else {
        std::result::Result::Ok(())
    }
}


    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetKeyPathParams {
            /// URL-encoded SAE ID of slave SAE
                pub slave_sae_id: String,
    }



    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetKeySimplePathParams {
            /// URL-encoded SAE ID of slave SAE
                pub slave_sae_id: String,
    }


    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetKeySimpleQueryParams {
            /// Number of keys requested (default 1)
                #[serde(rename = "number")]
                #[validate(
                        range(min = 1i32),
              )]
                    #[serde(skip_serializing_if="Option::is_none")]
                    pub number: Option<i32>,
            /// Size of each key in bits (default is key_size from Status). Some KMEs require a multiple of 8 and may return 400 with message \"size shall be a multiple of 8\". 
                #[serde(rename = "size")]
                #[validate(
                        range(min = 1i32),
              )]
                    #[serde(skip_serializing_if="Option::is_none")]
                    pub size: Option<i32>,
    }


    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetKeyWithIdsPathParams {
            /// URL-encoded SAE ID of master SAE
                pub master_sae_id: String,
    }



    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetKeyWithIdsSimplePathParams {
            /// URL-encoded SAE ID of master SAE
                pub master_sae_id: String,
    }


    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetKeyWithIdsSimpleQueryParams {
            /// ID of the key (UUID)
                #[serde(rename = "key_ID")]
                    pub key_id: uuid::Uuid,
    }


    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
    #[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
    pub struct GetStatusPathParams {
            /// URL-encoded SAE ID of slave SAE
                pub slave_sae_id: String,
    }




#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct Error {
    #[serde(rename = "message")]
          #[validate(custom(function = "check_xss_string"))]
    pub message: String,

    #[serde(rename = "details")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub details: Option<Vec<std::collections::HashMap<String, crate::types::Object>>>,

}



impl Error {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(message: String, ) -> Error {
        Error {
 message,
 details: None,
        }
    }
}

/// Converts the Error value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            Some("message".to_string()),
            Some(self.message.to_string()),

            // Skipping details in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a Error value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for Error {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub message: Vec<String>,
            pub details: Vec<Vec<std::collections::HashMap<String, crate::types::Object>>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing Error".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "message" => intermediate_rep.message.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "details" => return std::result::Result::Err("Parsing a container in this style is not supported in Error".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing Error".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(Error {
            message: intermediate_rep.message.into_iter().next().ok_or_else(|| "message missing in Error".to_string())?,
            details: intermediate_rep.details.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<Error> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<Error>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<Error>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for Error - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<Error> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <Error as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into Error - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct KeyContainer {
    #[serde(rename = "keys")]
          #[validate(nested)]
    pub keys: Vec<models::KeyItem>,

    /// Optional, for future use
    #[serde(rename = "key_container_extension")]
          #[validate(custom(function = "check_xss_map"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub key_container_extension: Option<std::collections::HashMap<String, crate::types::Object>>,

}



impl KeyContainer {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(keys: Vec<models::KeyItem>, ) -> KeyContainer {
        KeyContainer {
 keys,
 key_container_extension: None,
        }
    }
}

/// Converts the KeyContainer value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for KeyContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping keys in query parameter serialization

            // Skipping key_container_extension in query parameter serialization
            // Skipping key_container_extension in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a KeyContainer value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for KeyContainer {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub keys: Vec<Vec<models::KeyItem>>,
            pub key_container_extension: Vec<std::collections::HashMap<String, crate::types::Object>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing KeyContainer".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    "keys" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyContainer".to_string()),
                    "key_container_extension" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyContainer".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing KeyContainer".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(KeyContainer {
            keys: intermediate_rep.keys.into_iter().next().ok_or_else(|| "keys missing in KeyContainer".to_string())?,
            key_container_extension: intermediate_rep.key_container_extension.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<KeyContainer> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<KeyContainer>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<KeyContainer>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for KeyContainer - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<KeyContainer> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <KeyContainer as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into KeyContainer - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct KeyIdItem {
    /// ID of the key (UUID)
    #[serde(rename = "key_ID")]
    pub key_id: uuid::Uuid,

    /// Optional, for future use
    #[serde(rename = "key_ID_extension")]
          #[validate(custom(function = "check_xss_map"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub key_id_extension: Option<std::collections::HashMap<String, crate::types::Object>>,

}



impl KeyIdItem {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(key_id: uuid::Uuid, ) -> KeyIdItem {
        KeyIdItem {
 key_id,
 key_id_extension: None,
        }
    }
}

/// Converts the KeyIdItem value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for KeyIdItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping key_ID in query parameter serialization

            // Skipping key_ID_extension in query parameter serialization
            // Skipping key_ID_extension in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a KeyIdItem value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for KeyIdItem {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub key_id: Vec<uuid::Uuid>,
            pub key_id_extension: Vec<std::collections::HashMap<String, crate::types::Object>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing KeyIdItem".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "key_ID" => intermediate_rep.key_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "key_ID_extension" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyIdItem".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing KeyIdItem".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(KeyIdItem {
            key_id: intermediate_rep.key_id.into_iter().next().ok_or_else(|| "key_ID missing in KeyIdItem".to_string())?,
            key_id_extension: intermediate_rep.key_id_extension.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<KeyIdItem> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<KeyIdItem>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<KeyIdItem>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for KeyIdItem - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<KeyIdItem> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <KeyIdItem as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into KeyIdItem - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct KeyIds {
    #[serde(rename = "key_IDs")]
          #[validate(nested)]
    pub key_ids: Vec<models::KeyIdItem>,

    /// Optional, for future use
    #[serde(rename = "key_IDs_extension")]
          #[validate(custom(function = "check_xss_map"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub key_ids_extension: Option<std::collections::HashMap<String, crate::types::Object>>,

}



impl KeyIds {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(key_ids: Vec<models::KeyIdItem>, ) -> KeyIds {
        KeyIds {
 key_ids,
 key_ids_extension: None,
        }
    }
}

/// Converts the KeyIds value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for KeyIds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping key_IDs in query parameter serialization

            // Skipping key_IDs_extension in query parameter serialization
            // Skipping key_IDs_extension in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a KeyIds value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for KeyIds {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub key_ids: Vec<Vec<models::KeyIdItem>>,
            pub key_ids_extension: Vec<std::collections::HashMap<String, crate::types::Object>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing KeyIds".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    "key_IDs" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyIds".to_string()),
                    "key_IDs_extension" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyIds".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing KeyIds".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(KeyIds {
            key_ids: intermediate_rep.key_ids.into_iter().next().ok_or_else(|| "key_IDs missing in KeyIds".to_string())?,
            key_ids_extension: intermediate_rep.key_ids_extension.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<KeyIds> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<KeyIds>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<KeyIds>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for KeyIds - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<KeyIds> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <KeyIds as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into KeyIds - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct KeyItem {
    /// ID of the key (UUID)
    #[serde(rename = "key_ID")]
    pub key_id: uuid::Uuid,

    /// Optional, for future use
    #[serde(rename = "key_ID_extension")]
          #[validate(custom(function = "check_xss_map"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub key_id_extension: Option<std::collections::HashMap<String, crate::types::Object>>,

    /// Key data encoded by base64
    #[serde(rename = "key")]
    pub key: ByteArray,

    /// Optional, for future use
    #[serde(rename = "key_extension")]
          #[validate(custom(function = "check_xss_map"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub key_extension: Option<std::collections::HashMap<String, crate::types::Object>>,

}



impl KeyItem {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(key_id: uuid::Uuid, key: ByteArray, ) -> KeyItem {
        KeyItem {
 key_id,
 key_id_extension: None,
 key,
 key_extension: None,
        }
    }
}

/// Converts the KeyItem value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for KeyItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![
            // Skipping key_ID in query parameter serialization

            // Skipping key_ID_extension in query parameter serialization
            // Skipping key_ID_extension in query parameter serialization

            // Skipping key in query parameter serialization
            // Skipping key in query parameter serialization

            // Skipping key_extension in query parameter serialization
            // Skipping key_extension in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a KeyItem value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for KeyItem {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub key_id: Vec<uuid::Uuid>,
            pub key_id_extension: Vec<std::collections::HashMap<String, crate::types::Object>>,
            pub key: Vec<ByteArray>,
            pub key_extension: Vec<std::collections::HashMap<String, crate::types::Object>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing KeyItem".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "key_ID" => intermediate_rep.key_id.push(<uuid::Uuid as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "key_ID_extension" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyItem".to_string()),
                    "key" => return std::result::Result::Err("Parsing binary data in this style is not supported in KeyItem".to_string()),
                    "key_extension" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyItem".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing KeyItem".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(KeyItem {
            key_id: intermediate_rep.key_id.into_iter().next().ok_or_else(|| "key_ID missing in KeyItem".to_string())?,
            key_id_extension: intermediate_rep.key_id_extension.into_iter().next(),
            key: intermediate_rep.key.into_iter().next().ok_or_else(|| "key missing in KeyItem".to_string())?,
            key_extension: intermediate_rep.key_extension.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<KeyItem> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<KeyItem>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<KeyItem>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for KeyItem - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<KeyItem> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <KeyItem as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into KeyItem - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



/// All fields are optional; the JSON body may be empty. GET is only permitted for empty request or only number/size (as query params). 
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct KeyRequest {
    /// Number of keys requested (default 1)
    #[serde(rename = "number")]
    #[validate(
            range(min = 1u32),
    )]
    #[serde(skip_serializing_if="Option::is_none")]
    pub number: Option<u32>,

    /// Size of each key in bits (default key_size from Status)
    #[serde(rename = "size")]
    #[validate(
            range(min = 1u32),
    )]
    #[serde(skip_serializing_if="Option::is_none")]
    pub size: Option<u32>,

    /// Optional list of additional slave SAE IDs for key multicast
    #[serde(rename = "additional_slave_SAE_IDs")]
          #[validate(custom(function = "check_xss_vec_string"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub additional_slave_sae_ids: Option<Vec<String>>,

    /// Extensions that the KME must support or return 400
    #[serde(rename = "extension_mandatory")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub extension_mandatory: Option<Vec<std::collections::HashMap<String, crate::types::Object>>>,

    /// Extensions that the KME may ignore
    #[serde(rename = "extension_optional")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub extension_optional: Option<Vec<std::collections::HashMap<String, crate::types::Object>>>,

}



impl KeyRequest {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new() -> KeyRequest {
        KeyRequest {
 number: None,
 size: None,
 additional_slave_sae_ids: None,
 extension_mandatory: None,
 extension_optional: None,
        }
    }
}

/// Converts the KeyRequest value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for KeyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            self.number.as_ref().map(|number| {
                [
                    "number".to_string(),
                    number.to_string(),
                ].join(",")
            }),


            self.size.as_ref().map(|size| {
                [
                    "size".to_string(),
                    size.to_string(),
                ].join(",")
            }),


            self.additional_slave_sae_ids.as_ref().map(|additional_slave_sae_ids| {
                [
                    "additional_slave_SAE_IDs".to_string(),
                    additional_slave_sae_ids.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","),
                ].join(",")
            }),

            // Skipping extension_mandatory in query parameter serialization

            // Skipping extension_optional in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a KeyRequest value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for KeyRequest {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub number: Vec<u32>,
            pub size: Vec<u32>,
            pub additional_slave_sae_ids: Vec<Vec<String>>,
            pub extension_mandatory: Vec<Vec<std::collections::HashMap<String, crate::types::Object>>>,
            pub extension_optional: Vec<Vec<std::collections::HashMap<String, crate::types::Object>>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing KeyRequest".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "number" => intermediate_rep.number.push(<u32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "size" => intermediate_rep.size.push(<u32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "additional_slave_SAE_IDs" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyRequest".to_string()),
                    "extension_mandatory" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyRequest".to_string()),
                    "extension_optional" => return std::result::Result::Err("Parsing a container in this style is not supported in KeyRequest".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing KeyRequest".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(KeyRequest {
            number: intermediate_rep.number.into_iter().next(),
            size: intermediate_rep.size.into_iter().next(),
            additional_slave_sae_ids: intermediate_rep.additional_slave_sae_ids.into_iter().next(),
            extension_mandatory: intermediate_rep.extension_mandatory.into_iter().next(),
            extension_optional: intermediate_rep.extension_optional.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<KeyRequest> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<KeyRequest>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<KeyRequest>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for KeyRequest - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<KeyRequest> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <KeyRequest as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into KeyRequest - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}



#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, validator::Validate)]
#[cfg_attr(feature = "conversion", derive(frunk::LabelledGeneric))]
pub struct Status {
    #[serde(rename = "source_KME_ID")]
          #[validate(custom(function = "check_xss_string"))]
    pub source_kme_id: String,

    #[serde(rename = "target_KME_ID")]
          #[validate(custom(function = "check_xss_string"))]
    pub target_kme_id: String,

    #[serde(rename = "master_SAE_ID")]
          #[validate(custom(function = "check_xss_string"))]
    pub master_sae_id: String,

    #[serde(rename = "slave_SAE_ID")]
          #[validate(custom(function = "check_xss_string"))]
    pub slave_sae_id: String,

    #[serde(rename = "key_size")]
    pub key_size: i32,

    #[serde(rename = "stored_key_count")]
    pub stored_key_count: i32,

    #[serde(rename = "max_key_count")]
    pub max_key_count: i32,

    #[serde(rename = "max_key_per_request")]
    pub max_key_per_request: i32,

    #[serde(rename = "max_key_size")]
    pub max_key_size: i32,

    #[serde(rename = "min_key_size")]
    pub min_key_size: i32,

    /// \"0\" when the KME does not support key multicast
    #[serde(rename = "max_SAE_ID_count")]
    pub max_sae_id_count: i32,

    /// Optional, for future use
    #[serde(rename = "status_extension")]
          #[validate(custom(function = "check_xss_map"))]
    #[serde(skip_serializing_if="Option::is_none")]
    pub status_extension: Option<std::collections::HashMap<String, crate::types::Object>>,

}



impl Status {
    #[allow(clippy::new_without_default, clippy::too_many_arguments)]
    pub fn new(source_kme_id: String, target_kme_id: String, master_sae_id: String, slave_sae_id: String, key_size: i32, stored_key_count: i32, max_key_count: i32, max_key_per_request: i32, max_key_size: i32, min_key_size: i32, max_sae_id_count: i32, ) -> Status {
        Status {
 source_kme_id,
 target_kme_id,
 master_sae_id,
 slave_sae_id,
 key_size,
 stored_key_count,
 max_key_count,
 max_key_per_request,
 max_key_size,
 min_key_size,
 max_sae_id_count,
 status_extension: None,
        }
    }
}

/// Converts the Status value to the Query Parameters representation (style=form, explode=false)
/// specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde serializer
impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params: Vec<Option<String>> = vec![

            Some("source_KME_ID".to_string()),
            Some(self.source_kme_id.to_string()),


            Some("target_KME_ID".to_string()),
            Some(self.target_kme_id.to_string()),


            Some("master_SAE_ID".to_string()),
            Some(self.master_sae_id.to_string()),


            Some("slave_SAE_ID".to_string()),
            Some(self.slave_sae_id.to_string()),


            Some("key_size".to_string()),
            Some(self.key_size.to_string()),


            Some("stored_key_count".to_string()),
            Some(self.stored_key_count.to_string()),


            Some("max_key_count".to_string()),
            Some(self.max_key_count.to_string()),


            Some("max_key_per_request".to_string()),
            Some(self.max_key_per_request.to_string()),


            Some("max_key_size".to_string()),
            Some(self.max_key_size.to_string()),


            Some("min_key_size".to_string()),
            Some(self.min_key_size.to_string()),


            Some("max_SAE_ID_count".to_string()),
            Some(self.max_sae_id_count.to_string()),

            // Skipping status_extension in query parameter serialization
            // Skipping status_extension in query parameter serialization

        ];

        write!(f, "{}", params.into_iter().flatten().collect::<Vec<_>>().join(","))
    }
}

/// Converts Query Parameters representation (style=form, explode=false) to a Status value
/// as specified in https://swagger.io/docs/specification/serialization/
/// Should be implemented in a serde deserializer
impl std::str::FromStr for Status {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        /// An intermediate representation of the struct to use for parsing.
        #[derive(Default)]
        #[allow(dead_code)]
        struct IntermediateRep {
            pub source_kme_id: Vec<String>,
            pub target_kme_id: Vec<String>,
            pub master_sae_id: Vec<String>,
            pub slave_sae_id: Vec<String>,
            pub key_size: Vec<i32>,
            pub stored_key_count: Vec<i32>,
            pub max_key_count: Vec<i32>,
            pub max_key_per_request: Vec<i32>,
            pub max_key_size: Vec<i32>,
            pub min_key_size: Vec<i32>,
            pub max_sae_id_count: Vec<i32>,
            pub status_extension: Vec<std::collections::HashMap<String, crate::types::Object>>,
        }

        let mut intermediate_rep = IntermediateRep::default();

        // Parse into intermediate representation
        let mut string_iter = s.split(',');
        let mut key_result = string_iter.next();

        while key_result.is_some() {
            let val = match string_iter.next() {
                Some(x) => x,
                None => return std::result::Result::Err("Missing value while parsing Status".to_string())
            };

            if let Some(key) = key_result {
                #[allow(clippy::match_single_binding)]
                match key {
                    #[allow(clippy::redundant_clone)]
                    "source_KME_ID" => intermediate_rep.source_kme_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "target_KME_ID" => intermediate_rep.target_kme_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "master_SAE_ID" => intermediate_rep.master_sae_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "slave_SAE_ID" => intermediate_rep.slave_sae_id.push(<String as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "key_size" => intermediate_rep.key_size.push(<i32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "stored_key_count" => intermediate_rep.stored_key_count.push(<i32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "max_key_count" => intermediate_rep.max_key_count.push(<i32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "max_key_per_request" => intermediate_rep.max_key_per_request.push(<i32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "max_key_size" => intermediate_rep.max_key_size.push(<i32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "min_key_size" => intermediate_rep.min_key_size.push(<i32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    #[allow(clippy::redundant_clone)]
                    "max_SAE_ID_count" => intermediate_rep.max_sae_id_count.push(<i32 as std::str::FromStr>::from_str(val).map_err(|x| x.to_string())?),
                    "status_extension" => return std::result::Result::Err("Parsing a container in this style is not supported in Status".to_string()),
                    _ => return std::result::Result::Err("Unexpected key while parsing Status".to_string())
                }
            }

            // Get the next key
            key_result = string_iter.next();
        }

        // Use the intermediate representation to return the struct
        std::result::Result::Ok(Status {
            source_kme_id: intermediate_rep.source_kme_id.into_iter().next().ok_or_else(|| "source_KME_ID missing in Status".to_string())?,
            target_kme_id: intermediate_rep.target_kme_id.into_iter().next().ok_or_else(|| "target_KME_ID missing in Status".to_string())?,
            master_sae_id: intermediate_rep.master_sae_id.into_iter().next().ok_or_else(|| "master_SAE_ID missing in Status".to_string())?,
            slave_sae_id: intermediate_rep.slave_sae_id.into_iter().next().ok_or_else(|| "slave_SAE_ID missing in Status".to_string())?,
            key_size: intermediate_rep.key_size.into_iter().next().ok_or_else(|| "key_size missing in Status".to_string())?,
            stored_key_count: intermediate_rep.stored_key_count.into_iter().next().ok_or_else(|| "stored_key_count missing in Status".to_string())?,
            max_key_count: intermediate_rep.max_key_count.into_iter().next().ok_or_else(|| "max_key_count missing in Status".to_string())?,
            max_key_per_request: intermediate_rep.max_key_per_request.into_iter().next().ok_or_else(|| "max_key_per_request missing in Status".to_string())?,
            max_key_size: intermediate_rep.max_key_size.into_iter().next().ok_or_else(|| "max_key_size missing in Status".to_string())?,
            min_key_size: intermediate_rep.min_key_size.into_iter().next().ok_or_else(|| "min_key_size missing in Status".to_string())?,
            max_sae_id_count: intermediate_rep.max_sae_id_count.into_iter().next().ok_or_else(|| "max_SAE_ID_count missing in Status".to_string())?,
            status_extension: intermediate_rep.status_extension.into_iter().next(),
        })
    }
}

// Methods for converting between header::IntoHeaderValue<Status> and HeaderValue

#[cfg(feature = "server")]
impl std::convert::TryFrom<header::IntoHeaderValue<Status>> for HeaderValue {
    type Error = String;

    fn try_from(hdr_value: header::IntoHeaderValue<Status>) -> std::result::Result<Self, Self::Error> {
        let hdr_value = hdr_value.to_string();
        match HeaderValue::from_str(&hdr_value) {
             std::result::Result::Ok(value) => std::result::Result::Ok(value),
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Invalid header value for Status - value: {hdr_value} is invalid {e}"#))
        }
    }
}

#[cfg(feature = "server")]
impl std::convert::TryFrom<HeaderValue> for header::IntoHeaderValue<Status> {
    type Error = String;

    fn try_from(hdr_value: HeaderValue) -> std::result::Result<Self, Self::Error> {
        match hdr_value.to_str() {
             std::result::Result::Ok(value) => {
                    match <Status as std::str::FromStr>::from_str(value) {
                        std::result::Result::Ok(value) => std::result::Result::Ok(header::IntoHeaderValue(value)),
                        std::result::Result::Err(err) => std::result::Result::Err(format!(r#"Unable to convert header value '{value}' into Status - {err}"#))
                    }
             },
             std::result::Result::Err(e) => std::result::Result::Err(format!(r#"Unable to convert header: {hdr_value:?} to string: {e}"#))
        }
    }
}


