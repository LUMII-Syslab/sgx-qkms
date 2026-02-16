mod etsi014_handler;

#[tokio::main]
async fn main() {
    use std::io::Write;
    use std::sync::Arc;

    let addr = std::env::var("QKMS_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let handler = Arc::new(etsi014_handler::Etsi014Handler);
    let app = qkd014_server_gen::server::new(handler);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind TCP listener");

    println!("Server is active on http://{addr}");
    std::io::stdout().flush().expect("failed to flush stdout");
    axum::serve(listener, app)
        .await
        .expect("server error");
}
