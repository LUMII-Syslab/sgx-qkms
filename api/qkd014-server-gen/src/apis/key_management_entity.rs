use async_trait::async_trait;
use axum::extract::*;
use axum_extra::extract::CookieJar;
use bytes::Bytes;
use headers::Host;
use http::Method;
use serde::{Deserialize, Serialize};

use crate::{models, types::*};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum GetKeyResponse {
    /// Keys retrieved successfully
    Status200_KeysRetrievedSuccessfully
    (models::KeyContainer)
    ,
    /// Bad request format
    Status400_BadRequestFormat
    (models::Error)
    ,
    /// Unauthorized
    Status401_Unauthorized
    ,
    /// Error on server side
    Status503_ErrorOnServerSide
    (models::Error)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum GetKeySimpleResponse {
    /// Keys retrieved successfully
    Status200_KeysRetrievedSuccessfully
    (models::KeyContainer)
    ,
    /// Bad request format
    Status400_BadRequestFormat
    (models::Error)
    ,
    /// Unauthorized
    Status401_Unauthorized
    ,
    /// Error on server side
    Status503_ErrorOnServerSide
    (models::Error)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum GetKeyWithIdsResponse {
    /// Keys retrieved successfully
    Status200_KeysRetrievedSuccessfully
    (models::KeyContainer)
    ,
    /// Bad request format
    Status400_BadRequestFormat
    (models::Error)
    ,
    /// Unauthorized
    Status401_Unauthorized
    ,
    /// Error on server side
    Status503_ErrorOnServerSide
    (models::Error)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum GetKeyWithIdsSimpleResponse {
    /// Keys retrieved successfully
    Status200_KeysRetrievedSuccessfully
    (models::KeyContainer)
    ,
    /// Bad request format
    Status400_BadRequestFormat
    (models::Error)
    ,
    /// Unauthorized
    Status401_Unauthorized
    ,
    /// Error on server side
    Status503_ErrorOnServerSide
    (models::Error)
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[must_use]
#[allow(clippy::large_enum_variant)]
pub enum GetStatusResponse {
    /// Status retrieved successfully
    Status200_StatusRetrievedSuccessfully
    (models::Status)
    ,
    /// Bad request format
    Status400_BadRequestFormat
    (models::Error)
    ,
    /// Unauthorized
    Status401_Unauthorized
    ,
    /// Error on server side
    Status503_ErrorOnServerSide
    (models::Error)
}




/// KeyManagementEntity
#[async_trait]
#[allow(clippy::ptr_arg)]
pub trait KeyManagementEntity<E: std::fmt::Debug + Send + Sync + 'static = ()>: super::ErrorHandler<E> {
    /// Get keys.
    ///
    /// GetKey - POST /api/v1/keys/{slave_SAE_ID}/enc_keys
    async fn get_key(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
      path_params: &models::GetKeyPathParams,
            body: &Option<models::KeyRequest>,
    ) -> Result<GetKeyResponse, E>;

    /// Get keys (simple GET form).
    ///
    /// GetKeySimple - GET /api/v1/keys/{slave_SAE_ID}/enc_keys
    async fn get_key_simple(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
      path_params: &models::GetKeySimplePathParams,
      query_params: &models::GetKeySimpleQueryParams,
    ) -> Result<GetKeySimpleResponse, E>;

    /// Get keys with key IDs.
    ///
    /// GetKeyWithIds - POST /api/v1/keys/{master_SAE_ID}/dec_keys
    async fn get_key_with_ids(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
      path_params: &models::GetKeyWithIdsPathParams,
            body: &models::KeyIds,
    ) -> Result<GetKeyWithIdsResponse, E>;

    /// Get keys with key ID (simple GET form).
    ///
    /// GetKeyWithIdsSimple - GET /api/v1/keys/{master_SAE_ID}/dec_keys
    async fn get_key_with_ids_simple(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
      path_params: &models::GetKeyWithIdsSimplePathParams,
      query_params: &models::GetKeyWithIdsSimpleQueryParams,
    ) -> Result<GetKeyWithIdsSimpleResponse, E>;

    /// Get status of keys available.
    ///
    /// GetStatus - GET /api/v1/keys/{slave_SAE_ID}/status
    async fn get_status(
    &self,
    
    method: &Method,
    host: &Host,
    cookies: &CookieJar,
      path_params: &models::GetStatusPathParams,
    ) -> Result<GetStatusResponse, E>;
}
