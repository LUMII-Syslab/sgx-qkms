use async_trait::async_trait;
use axum_extra::extract::CookieJar;
use headers::Host;
use http::Method;
use qkd014_server_gen::apis::ErrorHandler;
use qkd014_server_gen::apis::key_management_entity::{
    GetKeyResponse, GetKeySimpleResponse, GetKeyWithIdsResponse, GetKeyWithIdsSimpleResponse,
    GetStatusResponse, KeyManagementEntity,
};
use qkd014_server_gen::models;

/// Placeholder ETSI GS QKD 014 handler.
///
/// All endpoints currently return a generated 503 response with a descriptive
/// payload until business logic is implemented.
#[derive(Debug, Clone, Default)]
pub struct Etsi014Handler;

impl ErrorHandler<()> for Etsi014Handler {}

#[async_trait]
impl KeyManagementEntity<()> for Etsi014Handler {
    async fn get_key(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _path_params: &models::GetKeyPathParams,
        _body: &Option<models::KeyRequest>,
    ) -> Result<GetKeyResponse, ()> {
        Ok(GetKeyResponse::Status503_ErrorOnServerSide(
            models::Error::new("GetKey is not implemented yet".to_string()),
        ))
    }

    async fn get_key_simple(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _path_params: &models::GetKeySimplePathParams,
        _query_params: &models::GetKeySimpleQueryParams,
    ) -> Result<GetKeySimpleResponse, ()> {
        Ok(GetKeySimpleResponse::Status503_ErrorOnServerSide(
            models::Error::new("GetKeySimple is not implemented yet".to_string()),
        ))
    }

    async fn get_key_with_ids(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _path_params: &models::GetKeyWithIdsPathParams,
        _body: &models::KeyIds,
    ) -> Result<GetKeyWithIdsResponse, ()> {
        Ok(GetKeyWithIdsResponse::Status503_ErrorOnServerSide(
            models::Error::new("GetKeyWithIds is not implemented yet".to_string()),
        ))
    }

    async fn get_key_with_ids_simple(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        _path_params: &models::GetKeyWithIdsSimplePathParams,
        _query_params: &models::GetKeyWithIdsSimpleQueryParams,
    ) -> Result<GetKeyWithIdsSimpleResponse, ()> {
        Ok(GetKeyWithIdsSimpleResponse::Status503_ErrorOnServerSide(
            models::Error::new("GetKeyWithIdsSimple is not implemented yet".to_string()),
        ))
    }

    async fn get_status(
        &self,
        _method: &Method,
        _host: &Host,
        _cookies: &CookieJar,
        path_params: &models::GetStatusPathParams,
    ) -> Result<GetStatusResponse, ()> {
        let status = models::Status::new(
            "placeholder-source-kme".to_string(),
            "placeholder-target-kme".to_string(),
            "placeholder-master-sae".to_string(),
            path_params.slave_sae_id.clone(),
            256,
            0,
            100,
            10,
            512,
            128,
            0,
        );
        Ok(GetStatusResponse::Status200_StatusRetrievedSuccessfully(
            status,
        ))
    }
}

