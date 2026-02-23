use std::error::Error;
use std::io::Read;

pub enum HttpMethod {
    Get,
    Post,
    Other,
}

pub struct ParsedRequest {
    pub method: HttpMethod,
    pub path: String,
}

pub struct HttpResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl HttpResponse {
    pub fn to_http_bytes(&self) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            404 => "Not Found",
            405 => "Method Not Allowed",
            503 => "Service Unavailable",
            _ => "Internal Server Error",
        };

        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.status,
            status_text,
            self.content_type,
            self.body.len(),
            self.body
        );
        response.into_bytes()
    }
}

pub fn read_http_request(stream: &mut impl Read) -> Result<String, Box<dyn Error>> {
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 1024];

    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);

        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err("request headers too large".into());
        }
    }

    Ok(String::from_utf8_lossy(&buf).to_string())
}

pub fn parse_http_request(request: &str) -> Result<ParsedRequest, Box<dyn Error>> {
    let line = request.lines().next().ok_or("empty HTTP request received")?;
    let mut parts = line.split_whitespace();

    let method = match parts.next().ok_or("missing HTTP method")? {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        _ => HttpMethod::Other,
    };

    let raw_path = parts.next().ok_or("missing request path")?;
    let path = raw_path.split('?').next().unwrap_or(raw_path);

    Ok(ParsedRequest {
        method,
        path: path.to_string(),
    })
}
