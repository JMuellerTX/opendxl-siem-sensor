mod dxl;
mod tls;
mod mqtt;

use dxl::parse_dxl_message;
use rumqttc::{AsyncClient, MqttOptions, QoS};
use std::time::Duration;
use log::{info, error, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Starting OpenDXL SIEM Sensor v1 (Rust)");

    // For testing, connect to a local broker 
    // Usually, you would read DXL client config (certificates, broker list)
    let mut mqttoptions = MqttOptions::new("rust-siem-sensor", "127.0.0.1", 8883);
    mqttoptions.set_keep_alive(Duration::from_secs(60));
    
    // TODO: Add TLS configuration based on ePO client provisioning (rustls)
    // mqttoptions.set_transport(rumqttc::Transport::Tls(...));

    let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

    info!("Subscribing to /mcafee/event/dxl/svcregistry/#");
    client.subscribe("/mcafee/event/dxl/svcregistry/#", QoS::AtMostOnce).await?;

    loop {
        match eventloop.poll().await {
            Ok(notification) => {
                if let rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish)) = notification {
                    info!("Received event on topic: {}", publish.topic);
                    
                    match parse_dxl_message(&publish.payload) {
                        Ok(msg) => {
                            info!("Decoded DXL Message: ID={} Type={}", msg.message_id, msg.message_type);
                            
                            // Normalise and Detect
                            handle_service_registry_event(&msg.payload);
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

fn handle_service_registry_event(payload: &[u8]) {
    if let Ok(json_str) = std::str::from_utf8(payload) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
            info!("Registry Event Payload: {}", value);
            
            // Basic detection logic (v1 placeholders)
            if let Some(event_type) = value.get("serviceType") {
                if event_type == "unregister" {
                    info!("[DETECTION] Service unregistered: {:?}", value.get("serviceId"));
                } else if event_type == "register" {
                    info!("[DETECTION] Service registered: {:?}", value.get("serviceId"));
                }
            }

            // Extract cert thumbprint
            if let Some(thumbprint) = value.get("clientCertificateThumbprint") {
                info!("[DETECTION] New client certificate thumbprint seen: {}", thumbprint);
            }
        } else {
            warn!("Payload is not valid JSON");
        }
    }
}
