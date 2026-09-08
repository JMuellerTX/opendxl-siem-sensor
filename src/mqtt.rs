use crate::tls::NoHostnameVerifier;
use rumqttc::{MqttOptions, Transport};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fmt;
use std::sync::Arc;

/// Why the TLS material could not be turned into a client configuration.
///
/// Every variant names the file it came from. A sensor that stops because a
/// path is wrong should say which path, not print a backtrace: the operator
/// reading it is usually looking at a provisioning directory, not at this
/// source.
#[derive(Debug)]
pub enum TlsSetupError {
    Certificates { path: String, reason: String },
    PrivateKey { path: String, reason: String },
    ClientAuth { reason: String },
    Verifier { reason: String },
}

impl fmt::Display for TlsSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsSetupError::Certificates { path, reason } => {
                write!(f, "cannot read certificates from {path}: {reason}")
            }
            TlsSetupError::PrivateKey { path, reason } => {
                write!(f, "cannot read the private key from {path}: {reason}")
            }
            TlsSetupError::ClientAuth { reason } => {
                write!(f, "the client certificate and key were rejected: {reason}")
            }
            TlsSetupError::Verifier { reason } => {
                write!(f, "cannot build the certificate verifier: {reason}")
            }
        }
    }
}

impl std::error::Error for TlsSetupError {}

// PEM parsing comes from rustls-pki-types, which rustls brings anyway.
// rustls-pemfile, the crate that used to do this, is unmaintained
// (RUSTSEC-2025-0134) and its API moved here.
#[allow(dead_code)]
pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsSetupError> {
    let fail = |reason: String| TlsSetupError::Certificates {
        path: path.to_string(),
        reason,
    };
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| fail(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| fail(e.to_string()))?;
    if certs.is_empty() {
        // An empty file parses cleanly and then fails much later, during the
        // handshake, as something unrelated-looking.
        return Err(fail("no certificate found in the file".to_string()));
    }
    Ok(certs)
}

#[allow(dead_code)]
pub fn load_keys(path: &str) -> Result<PrivateKeyDer<'static>, TlsSetupError> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| TlsSetupError::PrivateKey {
        path: path.to_string(),
        reason: e.to_string(),
    })
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
) -> Result<MqttOptions, TlsSetupError> {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(load_certs(ca_cert_path)?);

    let client_certs = load_certs(client_cert_path)?;
    let client_key = load_keys(client_key_path)?;

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store.clone())
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| TlsSetupError::ClientAuth {
            reason: e.to_string(),
        })?;

    if !verify_hostname {
        let verifier =
            NoHostnameVerifier::new(Arc::new(root_store)).map_err(|e| TlsSetupError::Verifier {
                reason: e.to_string(),
            })?;
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(verifier));
    }

    let mut mqttoptions = MqttOptions::new(client_id, host, port);
    mqttoptions.set_transport(Transport::tls_with_config(client_config.into()));
    Ok(mqttoptions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rumqttc::AsyncClient;
    use std::io::Write;
    use std::time::Duration;

    fn write_temp(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dxl-sensor-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).expect("temp file");
        file.write_all(contents).expect("write");
        path
    }

    // These four say the same thing in four ways: a bad file has to come back
    // as a message naming that file, not as a panic. The sensor is started by
    // people who are looking at a provisioning directory.

    #[test]
    fn a_missing_certificate_file_names_the_path() {
        let error = load_certs("does-not-exist.crt").expect_err("missing file must fail");
        let message = error.to_string();
        assert!(message.contains("does-not-exist.crt"), "{message}");
        assert!(message.contains("cannot read certificates"), "{message}");
    }

    #[test]
    fn a_file_without_a_certificate_is_reported_rather_than_accepted() {
        let path = write_temp("empty.crt", b"# no PEM here\n");
        let error = load_certs(path.to_str().unwrap()).expect_err("empty file must fail");
        assert!(
            error.to_string().contains("no certificate found"),
            "{error}"
        );
    }

    #[test]
    fn a_missing_key_file_names_the_path() {
        let error = load_keys("does-not-exist.key").expect_err("missing file must fail");
        let message = error.to_string();
        assert!(message.contains("does-not-exist.key"), "{message}");
        assert!(message.contains("private key"), "{message}");
    }

    #[test]
    fn building_the_options_fails_with_a_message_not_a_panic() {
        let error = build_mqtt_options(
            "test-client",
            "127.0.0.1",
            8883,
            "no-such-ca.crt",
            "no-such-client.crt",
            "no-such-client.key",
            false,
        )
        .expect_err("nothing here exists, so this must fail");
        assert!(error.to_string().contains("no-such-ca.crt"), "{error}");
    }

    #[tokio::test]
    async fn test_connectivity_dxl_modern() {
        let config_dir = match std::env::var("DXL_SENSOR_TEST_CONFIG_DIR") {
            Ok(dir) => dir,
            Err(_) => {
                println!(
                    "Skipping test_connectivity_dxl_modern: DXL_SENSOR_TEST_CONFIG_DIR not set"
                );
                return;
            }
        };
        let ca_path = format!("{}/ca-bundle.crt", config_dir);
        if !std::path::Path::new(&ca_path).exists() {
            println!(
                "Skipping test_connectivity_dxl_modern: ca-bundle.crt not found in {}",
                config_dir
            );
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
        )
        .expect("the test configuration should produce a usable TLS setup");
        mqttoptions.set_keep_alive(Duration::from_secs(5));

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);
        let _ = client
            .subscribe("/mcafee/test", rumqttc::QoS::AtMostOnce)
            .await;

        // Just poll once to ensure connection is established
        if let Ok(event) = eventloop.poll().await {
            println!("Received event: {:?}", event);
        }
    }

    #[tokio::test]
    async fn test_tls_versions_g9() {
        use crate::tls::NoHostnameVerifier;
        use rustls::ClientConfig;
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        let config_modern = std::env::var("DXL_SENSOR_TEST_CONFIG_DIR");
        let config_tls13 = std::env::var("DXL_SENSOR_TEST_CONFIG_DIR_TLS13");

        let mut configs = Vec::new();
        if let Ok(dir) = config_modern {
            configs.push((
                "dxl-modern (TLS 1.2)",
                18883,
                dir,
                "opendxl-siem-sensor",
                rustls::version::TLS12.version,
            ));
        }
        if let Ok(dir) = config_tls13 {
            configs.push((
                "dxl-tls13 (TLS 1.3)",
                58883,
                dir,
                "opendxl-siem-sensor-tls13",
                rustls::version::TLS13.version,
            ));
        }

        if configs.is_empty() {
            println!(
                "Skipping test_tls_versions_g9: Environment variables for test configs not set"
            );
            return;
        }

        for (name, port, path, _cn, _expected_version) in configs {
            let ca_path = format!("{}/ca-bundle.crt", path);
            if !std::path::Path::new(&ca_path).exists() {
                println!("Skipping {}: config not found", name);
                continue;
            }

            let mut root_store = rustls::RootCertStore::empty();
            let ca_certs = load_certs(&ca_path).expect("test CA bundle");
            for cert in ca_certs {
                root_store.add(cert).unwrap();
            }

            let client_certs =
                load_certs(&format!("{}/client.crt", path)).expect("test client certificate");
            let client_key = load_keys(&format!("{}/client.key", path)).expect("test client key");

            let verifier = NoHostnameVerifier::new(Arc::new(root_store)).unwrap();

            let client_config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_client_auth_cert(client_certs, client_key)
                .unwrap();

            let connector = TlsConnector::from(Arc::new(client_config));
            let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            let domain = ServerName::try_from("localhost").unwrap();

            let tls_stream = connector.connect(domain, stream).await.unwrap();
            let (_, connection) = tls_stream.into_inner();

            println!("--- {} ---", name);
            println!("Protocol: {:?}", connection.protocol_version().unwrap());
            println!(
                "Cipher: {:?}",
                connection.negotiated_cipher_suite().unwrap().suite()
            );
        }
    }

    #[tokio::test]
    async fn test_tls13_min_version_against_modern() {
        use crate::tls::NoHostnameVerifier;
        use rustls::ClientConfig;
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;

        let path = match std::env::var("DXL_SENSOR_TEST_CONFIG_DIR") {
            Ok(dir) => dir,
            Err(_) => {
                println!(
                    "Skipping test_tls13_min_version_against_modern: DXL_SENSOR_TEST_CONFIG_DIR not set"
                );
                return;
            }
        };
        let ca_path = format!("{}/ca-bundle.crt", path);
        if !std::path::Path::new(&ca_path).exists() {
            println!(
                "Skipping test_tls13_min_version_against_modern: config not found in {}",
                path
            );
            return;
        }

        let mut root_store = rustls::RootCertStore::empty();
        let ca_certs = load_certs(&ca_path).expect("test CA bundle");
        for cert in ca_certs {
            root_store.add(cert).unwrap();
        }

        let client_certs =
            load_certs(&format!("{}/client.crt", path)).expect("test client certificate");
        let client_key = load_keys(&format!("{}/client.key", path)).expect("test client key");

        let verifier = NoHostnameVerifier::new(Arc::new(root_store)).unwrap();

        let client_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_client_auth_cert(client_certs, client_key)
                .unwrap();

        let connector = TlsConnector::from(Arc::new(client_config));
        let stream = TcpStream::connect("127.0.0.1:18883").await.unwrap();
        let domain = ServerName::try_from("localhost").unwrap();

        let result = connector.connect(domain, stream).await;
        println!(
            "TLS 1.3 min version against dxl-modern result: {:?}",
            result
        );
        assert!(result.is_err());
    }
}
