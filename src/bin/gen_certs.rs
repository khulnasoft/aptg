use anyhow::Result;
use aptg::tls::certificate_simple::CertificateManager;
use std::fs;
use tracing_subscriber;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    println!("Generating self-signed certificates for aptg - Debian Mirror Redirector");

    // Create certs directory if it doesn't exist
    fs::create_dir_all("certs")?;

    // Generate server certificate
    let server_cert_path = "certs/server.pem";
    let server_key_path = "certs/server.key";

    CertificateManager::generate_self_signed_cert("localhost", server_cert_path, server_key_path)?;

    println!("✅ Server certificate generated: {}", server_cert_path);
    println!("✅ Server private key generated: {}", server_key_path);

    // Generate client certificate
    let client_cert_path = "certs/client.pem";
    let client_key_path = "certs/client.key";

    CertificateManager::generate_self_signed_cert("client", client_cert_path, client_key_path)?;

    println!("✅ Client certificate generated: {}", client_cert_path);
    println!("✅ Client private key generated: {}", client_key_path);

    // Copy server cert as CA for testing
    let ca_cert_path = "certs/ca.pem";
    fs::copy(server_cert_path, ca_cert_path)?;
    println!("✅ CA certificate created: {}", ca_cert_path);

    println!("\n🎉 Certificates generated successfully!");
    println!("\n📝 Usage:");
    println!("   HTTP Server:  http://localhost:8080");
    println!("   HTTPS Server: https://localhost:8443");
    println!("\n⚠️  Note: These are self-signed certificates for testing only.");
    println!("   For production, use certificates from a trusted CA.");

    Ok(())
}
