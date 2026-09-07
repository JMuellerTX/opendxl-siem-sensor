mod config;
mod dxl;
mod mqtt;
mod tls;

use config::DxlConfig;
use dxl::{encode_dxl_message, parse_dxl_message, DxlMessage, MESSAGE_TYPE_REQUEST};
use log::{error, info, warn};
use mqtt::build_mqtt_options;
use rumqttc::{AsyncClient, QoS};
use std::time::Duration;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Starting OpenDXL SIEM Sensor v1 (Rust)");

    let config_path = std::env::args().nth(1).unwrap_or_else(|| {
        "c:/src/opendxl/_local_verify/gemini-sensor-config/dxlclient.config".to_string()
    });
    info!("Loading config from: {}", config_path);
    
    let config = DxlConfig::load(config_path).expect("Failed to load config");
    let broker = config.brokers.first().expect("No brokers configured");
    
    let mut mqttoptions = build_mqtt_options(
        &config.client_id,
        &broker.ip,
        broker.port,
        &config.broker_cert_chain,
        &config.cert_file,
        &config.private_key,
        config.verify_hostname,
    );
    
    mqttoptions.set_keep_alive(Duration::from_secs(60));
    let (client, mut eventloop) = AsyncClient::new(mqttoptions, 100);
    
    let reply_to_topic = format!("/mcafee/client/{}", config.client_id);
    client.subscribe(&reply_to_topic, QoS::AtMostOnce).await?;
    info!("Subscribed to reply topic: {}", reply_to_topic);

    client.subscribe("/mcafee/event/dxl/#", QoS::AtMostOnce).await?;
    
    let svc_query_msg = DxlMessage {
        version: 3,
        message_type: MESSAGE_TYPE_REQUEST,
        message_id: Uuid::new_v4().to_string(),
        source_client_id: config.client_id.clone(),
        source_broker_id: "".to_string(),
        broker_ids: vec![],
        client_ids: vec![],
        payload: b"{}".to_vec(),
        reply_to_topic: Some(reply_to_topic.clone()),
        service_id: Some("".to_string()),
        request_message_id: None,
        error_code: None,
        error_message: None,
        other_fields: std::collections::HashMap::new(),
        source_tenant_guid: None,
        destination_tenant_guids: vec![],
        source_client_instance_id: None,
    };
    
    let encoded_svc_query = encode_dxl_message(&svc_query_msg)?;
    client.publish("/mcafee/service/dxl/svcregistry/query", QoS::AtMostOnce, false, encoded_svc_query).await?;
    info!("Sent svcregistry/query");

    let broker_query_msg = DxlMessage {
        message_id: Uuid::new_v4().to_string(),
        ..svc_query_msg
    };
    let encoded_broker_query = encode_dxl_message(&broker_query_msg)?;
    client.publish("/mcafee/service/dxl/brokerregistry/query", QoS::AtMostOnce, false, encoded_broker_query).await?;
    info!("Sent brokerregistry/query");

    loop {
        match eventloop.poll().await {
            Ok(notification) => {
                if let rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish)) = notification {
                    info!("Received event on topic: {}", publish.topic);
                    
                    match parse_dxl_message(&publish.payload) {
                        Ok(msg) => {
                            info!("Decoded DXL Message: ID={} Type={}", msg.message_id, msg.message_type);
                            
                            // Normalise and Detect
                            handle_service_registry_event(&publish.topic, &msg.payload);
                        }
                        Err(e) => {
                            error!("Failed to decode DXL message: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("MQTT Connection error: {}", e);
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

fn handle_service_registry_event(topic: &str, payload: &[u8]) {
    if let Ok(json_str) = std::str::from_utf8(payload) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
            info!("Registry Event Payload: {}", value);
            
            let service_guid = value.get("serviceGuid").and_then(|v| v.as_str()).unwrap_or("unknown");

            if topic.contains("svcregistry/register") {
                let service_type = value.get("serviceType").and_then(|v| v.as_str()).unwrap_or("unknown");
                info!("[DETECTION] Service registered: Guid={}, Type={}", service_guid, service_type);
                if let Some(certs) = value.get("certificates").and_then(|v| v.as_array()) {
                    for cert in certs {
                        info!("[DETECTION] Certificate thumbprint: {}", cert);
                    }
                }
            } else if topic.contains("svcregistry/unregister") {
                info!("[DETECTION] Service unregistered: Guid={}", service_guid);
            }
        } else {
            warn!("Payload is not valid JSON");
        }
    }
}
