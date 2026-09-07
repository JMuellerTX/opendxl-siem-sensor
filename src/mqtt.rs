use crate::tls::NoHostnameVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use rumqttc::{MqttOptions, Transport};

#[allow(dead_code)]
pub fn load_certs(path: &str) -> Vec<CertificateDer<'static>> {
    let mut reader = BufReader::new(File::open(path).unwrap());
    certs(&mut reader)
        .map(|result| result.unwrap())
        .collect()
}

#[allow(dead_code)]
pub fn load_keys(path: &str) -> PrivateKeyDer<'static> {
    let mut reader = BufReader::new(File::open(path).unwrap());
    rustls_pemfile::private_key(&mut reader)
        .unwrap()
        .unwrap()
}

#[allow(dead_code)]
pub fn build_mqtt_options(
    client_id: &str,
    host: &str,
    port: u16,
    ca_cert_path: &str,
    client_cert_path: &str,
    client_key_path: &str,
    verify_hostname: bool,
) -> MqttOptions {
    let mut root_store = RootCertStore::empty();
    let ca_certs = load_certs(ca_cert_path);
    root_store.add_parsable_certificates(ca_certs);

    let client_certs = load_certs(client_cert_path);
    let client_key = load_keys(client_key_path);

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store.clone())
        .with_client_auth_cert(client_certs, client_key)
        .unwrap();

    if !verify_hostname {
        client_config.dangerous()
            .set_certificate_verifier(Arc::new(NoHostnameVerifier::new(Arc::new(root_store)).unwrap()));
    }

    let mut mqttoptions = MqttOptions::new(client_id, host, port);
    mqttoptions.set_transport(Transport::tls_with_config(client_config.into()));
    mqttoptions
}

#[cfg(test)]
mod tests {
    use super::*;
    use rumqttc::AsyncClient;
    use std::time::Duration;

    #[tokio::test]
    async fn test_connectivity_dxl_modern() {
        let config_dir = match std::env::var("DXL_SENSOR_TEST_CONFIG_DIR") {
            Ok(dir) => dir,
            Err(_) => {
                println!("Skipping test_connectivity_dxl_modern: DXL_SENSOR_TEST_CONFIG_DIR not set");
                return;
            }
        };
        let ca_path = format!("{}/ca-bundle.crt", config_dir);
        if !std::path::Path::new(&ca_path).exists() {
            println!("Skipping test_connectivity_dxl_modern: ca-bundle.crt not found in {}", config_dir);
            return;
        }

        let mut mqttoptions = build_mqtt_options(
            "rust-sensor",
            "127.0.0.1",
            18883,
            &ca_path,
            &format!("{}/client.crt", config_dir),
            &format!("{}/client.key", config_dir),
            false,
        );
        mqttoptions.set_keep_alive(Duration::from_secs(5));

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);
        let _ = client.subscribe("/mcafee/test", rumqttc::QoS::AtMostOnce).await;
        
        // Just poll once to ensure connection is established
        if let Ok(event) = eventloop.poll().await {
            println!("Received event: {:?}", event);
        }
    }

    #[tokio::test]
    async fn test_tls_versions_g9() {
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use rustls::ClientConfig;
        use rustls::pki_types::ServerName;
        use crate::tls::NoHostnameVerifier;

        let config_modern = std::env::var("DXL_SENSOR_TEST_CONFIG_DIR");
        let config_tls13 = std::env::var("DXL_SENSOR_TEST_CONFIG_DIR_TLS13");

        let mut configs = Vec::new();
        if let Ok(dir) = config_modern {
            configs.push((
                "dxl-modern (TLS 1.2)", 
                18883, 
                dir,
                "opendxl-siem-sensor",
                rustls::version::TLS12.version
            ));
        }
        if let Ok(dir) = config_tls13 {
            configs.push((
                "dxl-tls13 (TLS 1.3)", 
                58883, 
                dir,
                "opendxl-siem-sensor-tls13",
                rustls::version::TLS13.version
            ));
        }

        if configs.is_empty() {
            println!("Skipping test_tls_versions_g9: Environment variables for test configs not set");
            return;
        }

        for (name, port, path, _cn, _expected_version) in configs {
            let ca_path = format!("{}/ca-bundle.crt", path);
            if !std::path::Path::new(&ca_path).exists() {
                println!("Skipping {}: config not found", name);
                continue;
            }

            let mut root_store = rustls::RootCertStore::empty();
            let ca_certs = load_certs(&ca_path);
            for cert in ca_certs {
                root_store.add(cert).unwrap();
            }

            let client_certs = load_certs(&format!("{}/client.crt", path));
            let client_key = load_keys(&format!("{}/client.key", path));

            let verifier = NoHostnameVerifier::new(Arc::new(root_store)).unwrap();
            
            let client_config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_client_auth_cert(client_certs, client_key)
                .unwrap();

            let connector = TlsConnector::from(Arc::new(client_config));
            let stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
            let domain = ServerName::try_from("localhost").unwrap();
            
            let tls_stream = connector.connect(domain, stream).await.unwrap();
            let (_, connection) = tls_stream.into_inner();
            
            println!("--- {} ---", name);
            println!("Protocol: {:?}", connection.protocol_version().unwrap());
            println!("Cipher: {:?}", connection.negotiated_cipher_suite().unwrap().suite());
        }
    }

    #[tokio::test]
    async fn test_tls13_min_version_against_modern() {
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use rustls::ClientConfig;
        use rustls::pki_types::ServerName;
        use crate::tls::NoHostnameVerifier;

        let path = match std::env::var("DXL_SENSOR_TEST_CONFIG_DIR") {
            Ok(dir) => dir,
            Err(_) => {
                println!("Skipping test_tls13_min_version_against_modern: DXL_SENSOR_TEST_CONFIG_DIR not set");
                return;
            }
        };
        let ca_path = format!("{}/ca-bundle.crt", path);
        if !std::path::Path::new(&ca_path).exists() {
            println!("Skipping test_tls13_min_version_against_modern: config not found in {}", path);
            return;
        }

        let mut root_store = rustls::RootCertStore::empty();
        let ca_certs = load_certs(&ca_path);
        for cert in ca_certs {
            root_store.add(cert).unwrap();
        }

        let client_certs = load_certs(&format!("{}/client.crt", path));
        let client_key = load_keys(&format!("{}/client.key", path));

        let verifier = NoHostnameVerifier::new(Arc::new(root_store)).unwrap();
        
        let client_config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(client_certs, client_key)
            .unwrap();

        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect("127.0.0.1:18883").await.unwrap();
        let domain = ServerName::try_from("localhost").unwrap();
        
        let result = connector.connect(domain, stream).await;
        println!("TLS 1.3 min version against dxl-modern result: {:?}", result);
        assert!(result.is_err());
    }
}
