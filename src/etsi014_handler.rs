use crate::api_models::{ErrorResponse, Status};
use crate::http_protocol::{HttpMethod, HttpResponse, ParsedRequest};
use serde::Serialize;

pub fn route_request(request: &ParsedRequest, client_identity: &str) -> HttpResponse {
    let endpoint = classify_endpoint(&request.path);

    match (&request.method, endpoint) {
        (HttpMethod::Get, Endpoint::Status { slave_sae_id }) => {
            return handle_get_status(slave_sae_id, client_identity);
        }
        (HttpMethod::Get, Endpoint::EncKeys) | (HttpMethod::Post, Endpoint::EncKeys) => {
            return handle_get_enc_keys();
        }
        (HttpMethod::Get, Endpoint::DecKeys) | (HttpMethod::Post, Endpoint::DecKeys) => {
            return handle_get_dec_keys();
        }
        (HttpMethod::Other, Endpoint::Status { .. })
        | (HttpMethod::Other, Endpoint::EncKeys)
        | (HttpMethod::Other, Endpoint::DecKeys)
        | (_, Endpoint::Status { .. }) => {
            return method_not_allowed();
        }
        (_, Endpoint::Unknown) => {}
    }

    handle_not_found()
}

fn handle_get_status(slave_sae_id: &str, client_identity: &str) -> HttpResponse {
    let status = Status {
        source_kme_id: "placeholder-source-kme".to_string(),
        target_kme_id: "placeholder-target-kme".to_string(),
        master_sae_id: client_identity.to_string(),
        slave_sae_id: slave_sae_id.to_string(),
        key_size: 256,
        stored_key_count: 0,
        max_key_count: 100,
        max_key_per_request: 10,
        max_key_size: 512,
        min_key_size: 128,
        max_sae_id_count: 0,
        status_extension: None,
    };
    json_response(200, &status)
}

fn handle_get_enc_keys() -> HttpResponse {
    not_implemented("GetKey/GetKeySimple is not implemented yet")
}

fn handle_get_dec_keys() -> HttpResponse {
    not_implemented("GetKeyWithIds/GetKeyWithIdsSimple is not implemented yet")
}

fn handle_not_found() -> HttpResponse {
    let payload = ErrorResponse {
        message: "Not Found".to_string(),
        details: None,
    };
    json_response(404, &payload)
}

fn method_not_allowed() -> HttpResponse {
    let payload = ErrorResponse {
        message: "Method Not Allowed".to_string(),
        details: None,
    };
    json_response(405, &payload)
}

fn not_implemented(message: &str) -> HttpResponse {
    let payload = ErrorResponse {
        message: message.to_string(),
        details: None,
    };
    json_response(503, &payload)
}

fn json_response<T: Serialize>(status: u16, payload: &T) -> HttpResponse {
    HttpResponse {
        status,
        content_type: "application/json",
        body: serde_json::to_string(payload).unwrap_or_else(|_| {
            "{\"message\":\"serialization error\",\"details\":null}".to_string()
        }),
    }
}

enum Endpoint<'a> {
    Status { slave_sae_id: &'a str },
    EncKeys,
    DecKeys,
    Unknown,
}

fn classify_endpoint(path: &str) -> Endpoint<'_> {
    if let Some(slave_sae_id) = extract_path_param(path, "/api/v1/keys/", "/status") {
        return Endpoint::Status { slave_sae_id };
    }

    if path.starts_with("/api/v1/keys/") && path.ends_with("/enc_keys") {
        return Endpoint::EncKeys;
    }

    if path.starts_with("/api/v1/keys/") && path.ends_with("/dec_keys") {
        return Endpoint::DecKeys;
    }

    Endpoint::Unknown
}

fn extract_path_param<'a>(path: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    if !path.starts_with(prefix) || !path.ends_with(suffix) {
        return None;
    }

    let start = prefix.len();
    let end = path.len().saturating_sub(suffix.len());
    if end <= start {
        return None;
    }
    Some(&path[start..end])
}

