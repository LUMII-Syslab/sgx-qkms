use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
};
use rustls_mbedcrypto_provider::mbedtls_crypto_provider;
use std::error::Error;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::{env, fs::File, sync::Arc};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    prelude::parse_x509_certificate,
};
mod etsi014_handler;
mod api_models;
mod http_protocol;

fn load_ca_cert() -> RootCertStore {
    const CA_CERT_PATH: &str = "certs/ca/ca.crt";

    let cert_file = File::open(CA_CERT_PATH)
        .unwrap_or_else(|e| panic!("Failed to open CA cert at {CA_CERT_PATH}: {e}"));
    let mut cert_reader = BufReader::new(cert_file);

    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("Failed to parse PEM certs from {CA_CERT_PATH}: {e}"));

    let mut root_store = RootCertStore::empty();
    let (added, ignored) = root_store.add_parsable_certificates(certs);
    if added == 0 {
        panic!("No CA certificates were loaded from {CA_CERT_PATH}");
    }
    if ignored > 0 {
        panic!("Ignored {ignored} CA certificates from {CA_CERT_PATH}");
    }

    root_store
}

fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    let cert_file =
        File::open(path).unwrap_or_else(|e| panic!("Failed to open cert file at {path}: {e}"));
    let mut cert_reader = BufReader::new(cert_file);

    rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("Failed to parse certs from {path}: {e}"))
}

fn load_private_key(path: &str) -> PrivateKeyDer<'static> {
    let key_file =
        File::open(path).unwrap_or_else(|e| panic!("Failed to open key file at {path}: {e}"));
    let mut key_reader = BufReader::new(key_file);

    rustls_pemfile::private_key(&mut key_reader)
        .unwrap_or_else(|e| panic!("Failed to parse private key from {path}: {e}"))
        .unwrap_or_else(|| panic!("No private key found in {path}"))
}

fn extract_client_identity(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, parsed_cert) = parse_x509_certificate(cert.as_ref()).ok()?;

    for extension in parsed_cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => return Some(dns.to_string()),
                    GeneralName::URI(uri) => return Some(uri.to_string()),
                    GeneralName::RFC822Name(email) => return Some(email.to_string()),
                    GeneralName::IPAddress(raw) if raw.len() == 4 => {
                        return Some(
                            std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string(),
                        );
                    }
                    GeneralName::IPAddress(raw) if raw.len() == 16 => {
                        let mut bytes = [0_u8; 16];
                        bytes.copy_from_slice(raw);
                        return Some(std::net::Ipv6Addr::from(bytes).to_string());
                    }
                    _ => {}
                }
            }
        }
    }
    None
}

fn run_sample_server() -> Result<(), Box<dyn Error>> {
    const ADDR: &str = "127.0.0.1:8443";
    const SERVER_CERT_PATH: &str = "certs/sae/server.crt";
    const SERVER_KEY_PATH: &str = "certs/sae/server.key";

    let ca_cert_store = load_ca_cert();
    let server_cert_chain = load_certs(SERVER_CERT_PATH);
    let server_key = load_private_key(SERVER_KEY_PATH);

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(ca_cert_store)).build()?;
    let server_config = ServerConfig::builder_with_provider(Arc::new(mbedtls_crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_cert_chain, server_key)?;

    let server_config = Arc::new(server_config);
    let listener = TcpListener::bind(ADDR)?;
    println!("sample mTLS server listening on {ADDR}");

    loop {
        let (tcp_stream, peer_addr) = match listener.accept() {
            Ok(conn) => conn,
            Err(e) => return Err(e.into()),
        };
        let server_config = server_config.clone();

        std::thread::spawn(move || {
            if let Err(e) = handle_tls_connection(tcp_stream, server_config) {
                eprintln!("serve failed for {peer_addr}: {e}");
            }
        });
    }
}

fn handle_tls_connection(
    mut tcp_stream: TcpStream,
    server_config: Arc<ServerConfig>,
) -> Result<(), Box<dyn Error>> {
    let mut server_conn = ServerConnection::new(server_config)?;
    while server_conn.is_handshaking() {
        server_conn.complete_io(&mut tcp_stream)?;
    }

    let client_identity = server_conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(extract_client_identity)
        .unwrap_or_else(|| "stranger".to_string());

    let mut tls_stream = StreamOwned::new(server_conn, tcp_stream);
    let request = http_protocol::read_http_request(&mut tls_stream)?;
    let parsed = http_protocol::parse_http_request(&request)?;
    let response = etsi014_handler::route_request(&parsed, &client_identity);
    tls_stream.write_all(&response.to_http_bytes())?;
    tls_stream.flush()?;
    println!("served request for '{client_identity}'");
    Ok(())
}

fn run_sample_client() -> Result<(), Box<dyn Error>> {
    const ADDR: &str = "127.0.0.1:8443";
    const CLIENT_CERT_PATH: &str = "certs/sae/client.crt";
    const CLIENT_KEY_PATH: &str = "certs/sae/client.key";

    let ca_cert_store = load_ca_cert();
    let client_cert_chain = load_certs(CLIENT_CERT_PATH);
    let client_key = load_private_key(CLIENT_KEY_PATH);

    let client_config = ClientConfig::builder_with_provider(Arc::new(mbedtls_crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(ca_cert_store)
        .with_client_auth_cert(client_cert_chain, client_key)?;

    let mut tcp_stream = TcpStream::connect(ADDR)?;
    let server_name = ServerName::try_from("localhost")?;
    let mut client_conn = ClientConnection::new(Arc::new(client_config), server_name)?;
    while client_conn.is_handshaking() {
        client_conn.complete_io(&mut tcp_stream)?;
    }
    let mut tls_stream = StreamOwned::new(client_conn, tcp_stream);

    tls_stream
        .write_all(
            b"GET /api/v1/keys/test-slave-sae2/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )?;
    tls_stream.flush()?;

    let mut response = Vec::new();
    let _ = tls_stream.read_to_end(&mut response);
    let response_text = String::from_utf8_lossy(&response);
    let json = response_text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.trim())
        .unwrap_or_else(|| response_text.trim());
    println!("{json}");

    Ok(())
}

fn main() {
    let mut args = env::args();
    let _program = args.next();
    let mode = args.next();

    match mode.as_deref() {
        Some("server") => {
            if let Err(e) = run_sample_server() {
                eprintln!("server error: {e}");
                std::process::exit(1);
            }
        }
        Some("client") => {
            if let Err(e) = run_sample_client() {
                eprintln!("client error: {e}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Usage:");
            eprintln!("  sgx-qkms server");
            eprintln!("  sgx-qkms client");
            std::process::exit(1);
        }
    }
}
