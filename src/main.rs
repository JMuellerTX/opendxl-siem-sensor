mod config;
mod dxl;
mod mqtt;
mod tls;
pub mod ocsf;
pub mod cef;
pub mod syslog;

use config::DxlConfig;
use dxl::{encode_dxl_message, parse_dxl_message, DxlMessage, MESSAGE_TYPE_REQUEST};
use log::{error, info};
use mqtt::build_mqtt_options;
use rumqttc::{AsyncClient, QoS};
use std::time::Duration;
use uuid::Uuid;
use ocsf::{OcsfEvent, NetworkActivity, ApiActivity, OcsfMetadata, OcsfApi, OcsfService, OcsfActor, OcsfUser};
use cef::format_cef;
use chrono::Utc;

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
    
    let syslog_tx = syslog::start_syslog_sender(&config).await;
    
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
                            if let Some(ocsf_event) = handle_dxl_message(&publish.topic, &msg) {
                                let cef_str = format_cef(&ocsf_event);
                                println!("Syslog Output: {}", cef_str);
                                
                                if let Some(tx) = &syslog_tx {
                                    let _ = tx.send(cef_str).await;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to decode DXL message: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                let err_str = format!("{:?}", e);
                if err_str.contains("PeerIncompatible(ServerTlsVersionIsDisabledByOurConfig)") {
                    error!("Broker offers no TLS >= {}; lower TlsMinVersion or upgrade the broker", config.tls_min_version);
                } else {
                    error!("MQTT Connection error: {}", e);
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

fn handle_dxl_message(topic: &str, msg: &DxlMessage) -> Option<OcsfEvent> {
    if let Ok(json_str) = std::str::from_utf8(&msg.payload) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
            let now = Utc::now().timestamp_millis();
            let metadata = OcsfMetadata::default();
            
            if topic.contains("clientregistry/connect") || topic.contains("clientregistry/disconnect") {
                let is_connect = topic.contains("connect");
                let client_guid = value.get("clientGuid").and_then(|v| v.as_str()).unwrap_or("unknown");
                
                let na = NetworkActivity {
                    activity_id: if is_connect { 1 } else { 2 },
                    activity_name: if is_connect { "Connect".to_string() } else { "Disconnect".to_string() },
                    category_uid: 4,
                    category_name: "Network Activity".to_string(),
                    class_uid: 4001,
                    class_name: "Network Activity".to_string(),
                    severity_id: 1,
                    severity: "Informational".to_string(),
                    time: now,
                    type_uid: if is_connect { 400101 } else { 400102 },
                    type_name: if is_connect { "Network Connect".to_string() } else { "Network Disconnect".to_string() },
                    metadata,
                    src_endpoint: None,
                    client_guid: client_guid.to_string(),
                };
                return Some(OcsfEvent::NetworkActivity(na));
                
            } else if topic.contains("svcregistry/register") || topic.contains("svcregistry/unregister") {
                let is_register = topic.contains("register");
                let service_guid = value.get("serviceGuid").and_then(|v| v.as_str()).unwrap_or("unknown");
                let service_type = value.get("serviceType").and_then(|v| v.as_str()).unwrap_or("unknown");
                let client_guid = value.get("clientGuid").and_then(|v| v.as_str());

                let actor = client_guid.map(|guid| OcsfActor {
                    user: OcsfUser { uid: guid.to_string() }
                });

                let aa = ApiActivity {
                    activity_id: if is_register { 2 } else { 4 },
                    activity_name: if is_register { "Register Service".to_string() } else { "Unregister Service".to_string() },
                    category_uid: 6,
                    category_name: "Application Activity".to_string(),
                    class_uid: 6003,
                    class_name: "API Activity".to_string(),
                    severity_id: 1,
                    severity: "Informational".to_string(),
                    time: now,
                    type_uid: if is_register { 600302 } else { 600304 },
                    type_name: if is_register { "Create API Activity".to_string() } else { "Delete API Activity".to_string() },
                    metadata,
                    api: OcsfApi {
                        operation: if is_register { "register".to_string() } else { "unregister".to_string() },
                        service: OcsfService {
                            name: service_type.to_string(),
                            uid: service_guid.to_string(),
                        },
                    },
                    actor,
                };
                return Some(OcsfEvent::ApiActivity(aa));
            } else if topic.contains("svcregistry/query") && msg.message_type == dxl::MESSAGE_TYPE_RESPONSE {
                info!("Received svcregistry/query response, to be normalized");
            } else if topic.contains("brokerregistry/query") && msg.message_type == dxl::MESSAGE_TYPE_RESPONSE {
                info!("Received brokerregistry/query response");
            } else {
                info!("Ignored event on topic {}", topic);
            }
        }
    }
    None
}
