use bytes::Bytes;
use futures::{future, future::BoxFuture, Stream, stream, future::FutureExt, stream::TryStreamExt};
use http_body_util::{combinators::BoxBody, Full};
use hyper::{body::{Body, Incoming}, HeaderMap, Request, Response, StatusCode};
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use log::warn;
#[cfg(feature = "validate")]
use serde_valid::Validate;
#[allow(unused_imports)]
use std::convert::{TryFrom, TryInto};
use std::{convert::Infallible, error::Error};
use std::future::Future;
use std::marker::PhantomData;
use std::task::{Context, Poll};
use swagger::{ApiError, BodyExt, Has, RequestParser, XSpanIdString};
pub use swagger::auth::Authorization;
use swagger::auth::Scopes;
use url::form_urlencoded;

#[allow(unused_imports)]
use crate::{models, header, AuthenticationApi};

pub use crate::context;

type ServiceFuture = BoxFuture<'static, Result<Response<BoxBody<Bytes, Infallible>>, crate::ServiceError>>;

use crate::{Api,
     GetKeyResponse,
     GetKeySimpleResponse,
     GetKeyWithIdsResponse,
     GetKeyWithIdsSimpleResponse,
     GetStatusResponse
};

mod server_auth;

mod paths {
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref GLOBAL_REGEX_SET: regex::RegexSet = regex::RegexSet::new(vec![
            r"^/api/v1/keys/(?P<master_SAE_ID>[^/?#]*)/dec_keys$",
            r"^/api/v1/keys/(?P<slave_SAE_ID>[^/?#]*)/enc_keys$",
            r"^/api/v1/keys/(?P<slave_SAE_ID>[^/?#]*)/status$"
        ])
        .expect("Unable to create global regex set");
    }
    pub(crate) static ID_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS: usize = 0;
    lazy_static! {
        pub static ref REGEX_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/api/v1/keys/(?P<master_SAE_ID>[^/?#]*)/dec_keys$")
                .expect("Unable to create regex for API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS");
    }
    pub(crate) static ID_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS: usize = 1;
    lazy_static! {
        pub static ref REGEX_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/api/v1/keys/(?P<slave_SAE_ID>[^/?#]*)/enc_keys$")
                .expect("Unable to create regex for API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS");
    }
    pub(crate) static ID_API_V1_KEYS_SLAVE_SAE_ID_STATUS: usize = 2;
    lazy_static! {
        pub static ref REGEX_API_V1_KEYS_SLAVE_SAE_ID_STATUS: regex::Regex =
            #[allow(clippy::invalid_regex)]
            regex::Regex::new(r"^/api/v1/keys/(?P<slave_SAE_ID>[^/?#]*)/status$")
                .expect("Unable to create regex for API_V1_KEYS_SLAVE_SAE_ID_STATUS");
    }
}


pub struct MakeService<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString>  + Send + Sync + 'static
{
    api_impl: T,
    marker: PhantomData<C>,
    validation: bool
}

impl<T, C> MakeService<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString>  + Send + Sync + 'static
{
    pub fn new(api_impl: T) -> Self {
        MakeService {
            api_impl,
            marker: PhantomData,
            validation: false
        }
    }

    // Turn on/off validation for the service being made.
    #[cfg(feature = "validate")]
    pub fn set_validation(&mut self, validation: bool) {
        self.validation = validation;
    }
}

impl<T, C> Clone for MakeService<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString>   + Send + Sync + 'static
{
    fn clone(&self) -> Self {
        Self {
            api_impl: self.api_impl.clone(),
            marker: PhantomData,
            validation: self.validation
        }
    }
}

impl<T, C, Target> hyper::service::Service<Target> for MakeService<T, C>
where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString>  + Send + Sync + 'static
{
    type Response = Service<T, C>;
    type Error = crate::ServiceError;
    type Future = future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, target: Target) -> Self::Future {
        let service = Service::new(self.api_impl.clone(), self.validation);

        future::ok(service)
    }
}

fn method_not_allowed() -> Result<Response<BoxBody<Bytes, Infallible>>, crate::ServiceError> {
    Ok(
        Response::builder().status(StatusCode::METHOD_NOT_ALLOWED)
            .body(BoxBody::new(http_body_util::Empty::new()))
            .expect("Unable to create Method Not Allowed response")
    )
}

#[allow(unused_macros)]
#[cfg(not(feature = "validate"))]
macro_rules! run_validation {
    ($parameter:tt, $base_name:tt, $validation:tt) => ();
}

#[allow(unused_macros)]
#[cfg(feature = "validate")]
macro_rules! run_validation {
    ($parameter:tt, $base_name:tt, $validation:tt) => {
        let $parameter = if $validation {
            match $parameter.validate() {
            Ok(()) => $parameter,
            Err(e) => return Ok(Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .header(CONTENT_TYPE, mime::TEXT_PLAIN.as_ref())
                                    .body(BoxBody::new(format!("Invalid value in body parameter {}: {}", $base_name, e)))
                                    .expect(&format!("Unable to create Bad Request response for invalid value in body parameter {}", $base_name))),
            }
        } else {
            $parameter
        };
    }
}

pub struct Service<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString>  + Send + Sync + 'static
{
    api_impl: T,
    marker: PhantomData<C>,
    // Enable regex pattern validation of received JSON models
    validation: bool,
}

impl<T, C> Service<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString>  + Send + Sync + 'static
{
    pub fn new(api_impl: T, validation: bool) -> Self {
        Service {
            api_impl,
            marker: PhantomData,
            validation,
        }
    }
    #[cfg(feature = "validate")]
    pub fn set_validation(&mut self, validation: bool) {
        self.validation = validation
    }

}

impl<T, C> Clone for Service<T, C> where
    T: Api<C> + Clone + Send + 'static,
    C: Has<XSpanIdString>  + Send + Sync + 'static
{
    fn clone(&self) -> Self {
        Service {
            api_impl: self.api_impl.clone(),
            marker: self.marker,
            validation: self.validation,
        }
    }
}

#[allow(dead_code)]
fn body_from_string(s: String) -> BoxBody<Bytes, Infallible> {
    BoxBody::new(Full::new(Bytes::from(s)))
}

fn body_from_str(s: &str) -> BoxBody<Bytes, Infallible> {
    BoxBody::new(Full::new(Bytes::copy_from_slice(s.as_bytes())))
}

impl<T, C, ReqBody> hyper::service::Service<(Request<ReqBody>, C)> for Service<T, C> where
    T: Api<C> + Clone + Send + Sync + 'static,
    C: Has<XSpanIdString>  + Send + Sync + 'static,
    ReqBody: Body + Send + 'static,
    ReqBody::Error: Into<Box<dyn Error + Send + Sync>> + Send,
    ReqBody::Data: Send,
{
    type Response = Response<BoxBody<Bytes, Infallible>>;
    type Error = crate::ServiceError;
    type Future = ServiceFuture;

    fn call(&self, req: (Request<ReqBody>, C)) -> Self::Future {
        async fn run<T, C, ReqBody>(
            mut api_impl: T,
            req: (Request<ReqBody>, C),
            validation: bool,
        ) -> Result<Response<BoxBody<Bytes, Infallible>>, crate::ServiceError>
        where
            T: Api<C> + Clone + Send + 'static,
            C: Has<XSpanIdString>  + Send + Sync + 'static,
            ReqBody: Body + Send + 'static,
            ReqBody::Error: Into<Box<dyn Error + Send + Sync>> + Send,
            ReqBody::Data: Send,
        {
            let (request, context) = req;
            let (parts, body) = request.into_parts();
            let (method, uri, headers) = (parts.method, parts.uri, parts.headers);
            let path = paths::GLOBAL_REGEX_SET.matches(uri.path());

            match method {

            // GetKey - POST /api/v1/keys/{slave_SAE_ID}/enc_keys
            hyper::Method::POST if path.matched(paths::ID_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS) => {
                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS in set but failed match against \"{}\"", path, paths::REGEX_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS.as_str())
                    );

                let param_slave_sae_id = match percent_encoding::percent_decode(path_params["slave_SAE_ID"].as_bytes()).decode_utf8() {
                    Ok(param_slave_sae_id) => match param_slave_sae_id.parse::<String>() {
                        Ok(param_slave_sae_id) => param_slave_sae_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't parse path parameter slave_SAE_ID: {e}")))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["slave_SAE_ID"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Handle body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = http_body_util::BodyExt::collect(body).await.map(|f| f.to_bytes().to_vec());
                match result {
                     Ok(body) => {
                                let mut unused_elements : Vec<String> = vec![];
                                let param_key_request: Option<models::KeyRequest> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    serde_ignored::deserialize(deserializer, |path| {
                                        warn!("Ignoring unknown field in body: {path}");
                                        unused_elements.push(path.to_string());
                                    }).unwrap_or_default()

                                } else {
                                    None
                                };
        #[cfg(not(feature = "validate"))]
                                run_validation!(param_key_request, "KeyRequest", validation);


                                let result = api_impl.get_key(
                                            param_slave_sae_id,
                                            param_key_request,
                                        &context
                                    ).await;
                                let mut response = Response::new(BoxBody::new(http_body_util::Empty::new()));
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {unused_elements:?}").as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }
                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetKeyResponse::KeysRetrievedSuccessfully
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetKeyResponse::BadRequestFormat
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 400 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetKeyResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");

                                                },
                                                GetKeyResponse::ErrorOnServerSide
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                            },
                                            Err(_) => {
                                                // Application code returned an error. This should not happen, as the implementation should
                                                // return a valid response.
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = body_from_str("An internal error occurred");
                                            },
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(body_from_string(format!("Unable to read body: {}", e.into())))
                                                .expect("Unable to create Bad Request response due to unable to read body")),
                        }
            },

            // GetKeySimple - GET /api/v1/keys/{slave_SAE_ID}/enc_keys
            hyper::Method::GET if path.matched(paths::ID_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS) => {
                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS in set but failed match against \"{}\"", path, paths::REGEX_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS.as_str())
                    );

                let param_slave_sae_id = match percent_encoding::percent_decode(path_params["slave_SAE_ID"].as_bytes()).decode_utf8() {
                    Ok(param_slave_sae_id) => match param_slave_sae_id.parse::<String>() {
                        Ok(param_slave_sae_id) => param_slave_sae_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't parse path parameter slave_SAE_ID: {e}")))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["slave_SAE_ID"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_number = query_params.iter().filter(|e| e.0 == "number").map(|e| e.1.clone())
                    .next();
                let param_number = match param_number {
                    Some(param_number) => {
                        let param_number =
                            <i32 as std::str::FromStr>::from_str
                                (&param_number);
                        match param_number {
                            Ok(param_number) => Some(param_number),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(body_from_string(format!("Couldn't parse query parameter number - doesn't match schema: {e}")))
                                .expect("Unable to create Bad Request response for invalid query parameter number")),
                        }
                    },
                    None => None,
                };
                let param_size = query_params.iter().filter(|e| e.0 == "size").map(|e| e.1.clone())
                    .next();
                let param_size = match param_size {
                    Some(param_size) => {
                        let param_size =
                            <i32 as std::str::FromStr>::from_str
                                (&param_size);
                        match param_size {
                            Ok(param_size) => Some(param_size),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(body_from_string(format!("Couldn't parse query parameter size - doesn't match schema: {e}")))
                                .expect("Unable to create Bad Request response for invalid query parameter size")),
                        }
                    },
                    None => None,
                };

                                let result = api_impl.get_key_simple(
                                            param_slave_sae_id,
                                            param_number,
                                            param_size,
                                        &context
                                    ).await;
                                let mut response = Response::new(BoxBody::new(http_body_util::Empty::new()));
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetKeySimpleResponse::KeysRetrievedSuccessfully
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetKeySimpleResponse::BadRequestFormat
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 400 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetKeySimpleResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");

                                                },
                                                GetKeySimpleResponse::ErrorOnServerSide
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                            },
                                            Err(_) => {
                                                // Application code returned an error. This should not happen, as the implementation should
                                                // return a valid response.
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = body_from_str("An internal error occurred");
                                            },
                                        }

                                        Ok(response)
            },

            // GetKeyWithIds - POST /api/v1/keys/{master_SAE_ID}/dec_keys
            hyper::Method::POST if path.matched(paths::ID_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS) => {
                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS in set but failed match against \"{}\"", path, paths::REGEX_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS.as_str())
                    );

                let param_master_sae_id = match percent_encoding::percent_decode(path_params["master_SAE_ID"].as_bytes()).decode_utf8() {
                    Ok(param_master_sae_id) => match param_master_sae_id.parse::<String>() {
                        Ok(param_master_sae_id) => param_master_sae_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't parse path parameter master_SAE_ID: {e}")))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["master_SAE_ID"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Handle body parameters (note that non-required body parameters will ignore garbage
                // values, rather than causing a 400 response). Produce warning header and logs for
                // any unused fields.
                let result = http_body_util::BodyExt::collect(body).await.map(|f| f.to_bytes().to_vec());
                match result {
                     Ok(body) => {
                                let mut unused_elements : Vec<String> = vec![];
                                let param_key_ids: Option<models::KeyIds> = if !body.is_empty() {
                                    let deserializer = &mut serde_json::Deserializer::from_slice(&body);
                                    match serde_ignored::deserialize(deserializer, |path| {
                                            warn!("Ignoring unknown field in body: {path}");
                                            unused_elements.push(path.to_string());
                                    }) {
                                        Ok(param_key_ids) => param_key_ids,
                                        Err(e) => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(BoxBody::new(format!("Couldn't parse body parameter KeyIds - doesn't match schema: {e}")))
                                                        .expect("Unable to create Bad Request response for invalid body parameter KeyIds due to schema")),
                                    }

                                } else {
                                    None
                                };
                                let param_key_ids = match param_key_ids {
                                    Some(param_key_ids) => param_key_ids,
                                    None => return Ok(Response::builder()
                                                        .status(StatusCode::BAD_REQUEST)
                                                        .body(BoxBody::new("Missing required body parameter KeyIds".to_string()))
                                                        .expect("Unable to create Bad Request response for missing body parameter KeyIds")),
                                };
        #[cfg(not(feature = "validate"))]
                                run_validation!(param_key_ids, "KeyIds", validation);


                                let result = api_impl.get_key_with_ids(
                                            param_master_sae_id,
                                            param_key_ids,
                                        &context
                                    ).await;
                                let mut response = Response::new(BoxBody::new(http_body_util::Empty::new()));
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        if !unused_elements.is_empty() {
                                            response.headers_mut().insert(
                                                HeaderName::from_static("warning"),
                                                HeaderValue::from_str(format!("Ignoring unknown fields in body: {unused_elements:?}").as_str())
                                                    .expect("Unable to create Warning header value"));
                                        }
                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetKeyWithIdsResponse::KeysRetrievedSuccessfully
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetKeyWithIdsResponse::BadRequestFormat
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 400 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetKeyWithIdsResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");

                                                },
                                                GetKeyWithIdsResponse::ErrorOnServerSide
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                            },
                                            Err(_) => {
                                                // Application code returned an error. This should not happen, as the implementation should
                                                // return a valid response.
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = body_from_str("An internal error occurred");
                                            },
                                        }

                                        Ok(response)
                            },
                            Err(e) => Ok(Response::builder()
                                                .status(StatusCode::BAD_REQUEST)
                                                .body(body_from_string(format!("Unable to read body: {}", e.into())))
                                                .expect("Unable to create Bad Request response due to unable to read body")),
                        }
            },

            // GetKeyWithIdsSimple - GET /api/v1/keys/{master_SAE_ID}/dec_keys
            hyper::Method::GET if path.matched(paths::ID_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS) => {
                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS in set but failed match against \"{}\"", path, paths::REGEX_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS.as_str())
                    );

                let param_master_sae_id = match percent_encoding::percent_decode(path_params["master_SAE_ID"].as_bytes()).decode_utf8() {
                    Ok(param_master_sae_id) => match param_master_sae_id.parse::<String>() {
                        Ok(param_master_sae_id) => param_master_sae_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't parse path parameter master_SAE_ID: {e}")))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["master_SAE_ID"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                // Query parameters (note that non-required or collection query parameters will ignore garbage values, rather than causing a 400 response)
                let query_params = form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect::<Vec<_>>();
                let param_key_id = query_params.iter().filter(|e| e.0 == "key_ID").map(|e| e.1.clone())
                    .next();
                let param_key_id = match param_key_id {
                    Some(param_key_id) => {
                        let param_key_id =
                            <uuid::Uuid as std::str::FromStr>::from_str
                                (&param_key_id);
                        match param_key_id {
                            Ok(param_key_id) => Some(param_key_id),
                            Err(e) => return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(body_from_string(format!("Couldn't parse query parameter key_ID - doesn't match schema: {e}")))
                                .expect("Unable to create Bad Request response for invalid query parameter key_ID")),
                        }
                    },
                    None => None,
                };
                let param_key_id = match param_key_id {
                    Some(param_key_id) => param_key_id,
                    None => return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(body_from_str("Missing required query parameter key_ID"))
                        .expect("Unable to create Bad Request response for missing query parameter key_ID")),
                };

                                let result = api_impl.get_key_with_ids_simple(
                                            param_master_sae_id,
                                            param_key_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(BoxBody::new(http_body_util::Empty::new()));
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetKeyWithIdsSimpleResponse::KeysRetrievedSuccessfully
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetKeyWithIdsSimpleResponse::BadRequestFormat
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 400 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetKeyWithIdsSimpleResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");

                                                },
                                                GetKeyWithIdsSimpleResponse::ErrorOnServerSide
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                            },
                                            Err(_) => {
                                                // Application code returned an error. This should not happen, as the implementation should
                                                // return a valid response.
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = body_from_str("An internal error occurred");
                                            },
                                        }

                                        Ok(response)
            },

            // GetStatus - GET /api/v1/keys/{slave_SAE_ID}/status
            hyper::Method::GET if path.matched(paths::ID_API_V1_KEYS_SLAVE_SAE_ID_STATUS) => {
                // Path parameters
                let path: &str = uri.path();
                let path_params =
                    paths::REGEX_API_V1_KEYS_SLAVE_SAE_ID_STATUS
                    .captures(path)
                    .unwrap_or_else(||
                        panic!("Path {} matched RE API_V1_KEYS_SLAVE_SAE_ID_STATUS in set but failed match against \"{}\"", path, paths::REGEX_API_V1_KEYS_SLAVE_SAE_ID_STATUS.as_str())
                    );

                let param_slave_sae_id = match percent_encoding::percent_decode(path_params["slave_SAE_ID"].as_bytes()).decode_utf8() {
                    Ok(param_slave_sae_id) => match param_slave_sae_id.parse::<String>() {
                        Ok(param_slave_sae_id) => param_slave_sae_id,
                        Err(e) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't parse path parameter slave_SAE_ID: {e}")))
                                        .expect("Unable to create Bad Request response for invalid path parameter")),
                    },
                    Err(_) => return Ok(Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(body_from_string(format!("Couldn't percent-decode path parameter as UTF-8: {}", &path_params["slave_SAE_ID"])))
                                        .expect("Unable to create Bad Request response for invalid percent decode"))
                };

                                let result = api_impl.get_status(
                                            param_slave_sae_id,
                                        &context
                                    ).await;
                                let mut response = Response::new(BoxBody::new(http_body_util::Empty::new()));
                                response.headers_mut().insert(
                                            HeaderName::from_static("x-span-id"),
                                            HeaderValue::from_str((&context as &dyn Has<XSpanIdString>).get().0.clone().as_str())
                                                .expect("Unable to create X-Span-ID header value"));

                                        match result {
                                            Ok(rsp) => match rsp {
                                                GetStatusResponse::StatusRetrievedSuccessfully
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(200).expect("Unable to turn 200 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetStatusResponse::BadRequestFormat
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(400).expect("Unable to turn 400 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                                GetStatusResponse::Unauthorized
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(401).expect("Unable to turn 401 into a StatusCode");

                                                },
                                                GetStatusResponse::ErrorOnServerSide
                                                    (body)
                                                => {
                                                    *response.status_mut() = StatusCode::from_u16(503).expect("Unable to turn 503 into a StatusCode");
                                                    response.headers_mut().insert(
                                                        CONTENT_TYPE,
                                                        HeaderValue::from_static("application/json"));
                                                    // JSON Body
                                                    let body = serde_json::to_string(&body).expect("impossible to fail to serialize");
                                                    *response.body_mut() = body_from_string(body);

                                                },
                                            },
                                            Err(_) => {
                                                // Application code returned an error. This should not happen, as the implementation should
                                                // return a valid response.
                                                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                                *response.body_mut() = body_from_str("An internal error occurred");
                                            },
                                        }

                                        Ok(response)
            },

            _ if path.matched(paths::ID_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS) => method_not_allowed(),
            _ if path.matched(paths::ID_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS) => method_not_allowed(),
            _ if path.matched(paths::ID_API_V1_KEYS_SLAVE_SAE_ID_STATUS) => method_not_allowed(),
                _ => Ok(Response::builder().status(StatusCode::NOT_FOUND)
                        .body(BoxBody::new(http_body_util::Empty::new()))
                        .expect("Unable to create Not Found response"))
            }
        }
        Box::pin(run(
            self.api_impl.clone(),
            req,
            self.validation
        ))
    }
}

/// Request parser for `Api`.
pub struct ApiRequestParser;
impl<T> RequestParser<T> for ApiRequestParser {
    fn parse_operation_id(request: &Request<T>) -> Option<&'static str> {
        let path = paths::GLOBAL_REGEX_SET.matches(request.uri().path());
        match *request.method() {
            // GetKey - POST /api/v1/keys/{slave_SAE_ID}/enc_keys
            hyper::Method::POST if path.matched(paths::ID_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS) => Some("GetKey"),
            // GetKeySimple - GET /api/v1/keys/{slave_SAE_ID}/enc_keys
            hyper::Method::GET if path.matched(paths::ID_API_V1_KEYS_SLAVE_SAE_ID_ENC_KEYS) => Some("GetKeySimple"),
            // GetKeyWithIds - POST /api/v1/keys/{master_SAE_ID}/dec_keys
            hyper::Method::POST if path.matched(paths::ID_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS) => Some("GetKeyWithIds"),
            // GetKeyWithIdsSimple - GET /api/v1/keys/{master_SAE_ID}/dec_keys
            hyper::Method::GET if path.matched(paths::ID_API_V1_KEYS_MASTER_SAE_ID_DEC_KEYS) => Some("GetKeyWithIdsSimple"),
            // GetStatus - GET /api/v1/keys/{slave_SAE_ID}/status
            hyper::Method::GET if path.matched(paths::ID_API_V1_KEYS_SLAVE_SAE_ID_STATUS) => Some("GetStatus"),
            _ => None,
        }
    }
}
