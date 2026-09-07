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
        let mut mqttoptions = build_mqtt_options(
            "rust-sensor",
            "127.0.0.1",
            18883,
            "c:/src/opendxl/_local_verify/gemini-sensor-config/ca-bundle.crt",
            "c:/src/opendxl/_local_verify/gemini-sensor-config/client.crt",
            "c:/src/opendxl/_local_verify/gemini-sensor-config/client.key",
            false,
        );
        mqttoptions.set_keep_alive(Duration::from_secs(5));
        
        let (_client, mut eventloop) = AsyncClient::new(mqttoptions, 10);
        
        match tokio::time::timeout(Duration::from_secs(3), eventloop.poll()).await {
            Ok(Ok(rumqttc::Event::Incoming(rumqttc::Packet::ConnAck(connack)))) => {
                assert_eq!(connack.code, rumqttc::ConnectReturnCode::Success);
            }
            res => panic!("Failed to connect or timed out: {:?}", res),
        }
    }
}
