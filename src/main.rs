pub mod cef;
mod cli;
mod config;
pub mod detections;
mod dxl;
pub mod http;
pub mod kafka;
mod mqtt;
pub mod ocsf;
pub mod syslog;
mod tls;

use cef::format_cef;
use chrono::{TimeZone, Utc};
use cli::{Cli, Format, Kind, ParseOutcome};
use config::DxlConfig;
use detections::DetectionEngine;
use dxl::{DxlMessage, MESSAGE_TYPE_REQUEST, encode_dxl_message, parse_dxl_message};
use log::{error, info};
use mqtt::build_mqtt_options;
use ocsf::{
    ApiActivity, NetworkActivity, OcsfActor, OcsfApi, OcsfEvent, OcsfMetadata, OcsfService,
    OcsfUser,
};
use rumqttc::{AsyncClient, QoS};
use std::io::Write;
use std::time::Duration;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = match Cli::from_env() {
        Ok(cli) => cli,
        // --help and --version are answers, not failures: they belong on stdout
        // and exit 0, so `opendxl-siem-sensor --help | less` behaves.
        Err(outcome @ (ParseOutcome::Help | ParseOutcome::Version)) => {
            println!("{outcome}");
            return Ok(());
        }
        Err(outcome) => {
            eprintln!("{outcome}");
            eprintln!();
            eprint!("{}", cli::USAGE);
            std::process::exit(2);
        }
    };

    let mut logger = env_logger::Builder::from_default_env();
    if std::env::var_os("RUST_LOG").is_none() {
        logger.filter_level(if cli.quiet {
            log::LevelFilter::Warn
        } else {
            log::LevelFilter::Info
        });
    }
    logger.init();
    info!("Starting OpenDXL SIEM Sensor v1 (Rust)");

    let Some(config_path) = cli.config.clone() else {
        eprintln!("Error: no client configuration given.");
        eprintln!("Pass it as an argument, with -c/--config, or in DXL_CONFIG.");
        eprintln!();
        eprint!("{}", cli::USAGE);
        std::process::exit(2);
    };
    info!("Loading config from: {}", config_path);

    let config = DxlConfig::load(&config_path).unwrap_or_else(|e| {
        eprintln!(
            "Error: Failed to load config file at '{}': {}",
            config_path, e
        );
        std::process::exit(2);
    });
    if config.brokers.is_empty() {
        eprintln!(
            "Error: {} lists no brokers in its [Brokers] section.",
            config_path
        );
        std::process::exit(2);
    }
    let (broker_target, broker_port) =
        select_broker_endpoint(&config.brokers, config.verify_hostname).await;

    // Exit code 2, the same as a configuration that cannot be read: a wrong
    // path or an unreadable certificate is a configuration problem, and the
    // message has to name the file. A panic here would print a backtrace to
    // someone who is looking at a provisioning directory, not at this source.
    let mut mqttoptions = build_mqtt_options(
        &config.client_id,
        &broker_target,
        broker_port,
        &config.broker_cert_chain,
        &config.cert_file,
        &config.private_key,
        config.verify_hostname,
        &config.tls_min_version,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(2);
    });

    mqttoptions.set_keep_alive(Duration::from_secs(60));
    let (client, mut eventloop) = AsyncClient::new(mqttoptions, 100);

    let syslog_tx = syslog::start_syslog_sender(&config).await;
    let http_tx = http::start_http_sender(&config).await;
    let kafka_tx = kafka::start_kafka_sender(&config).await;
    let mut detection_engine = DetectionEngine::new(&config);

    let reply_to_topic = format!("/mcafee/client/{}", config.client_id);
    let mut svc_query_msg_id = String::new();
    let mut broker_query_msg_id = String::new();

    let mut last_poll = Utc::now().timestamp();

    loop {
        // Use timeout to allow periodic polling for detections
        match tokio::time::timeout(Duration::from_secs(10), eventloop.poll()).await {
            Ok(Ok(notification)) => match notification {
                rumqttc::Event::Incoming(rumqttc::Packet::ConnAck(_)) => {
                    info!("Connected to broker; subscribing and syncing registry state");
                    match subscribe_and_sync(&client, &config, &reply_to_topic).await {
                        Ok((svc_id, broker_id)) => {
                            svc_query_msg_id = svc_id;
                            broker_query_msg_id = broker_id;
                        }
                        Err(e) => error!("Failed to subscribe and sync after ConnAck: {}", e),
                    }
                }
                rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish)) => {
                    info!("Received event on topic: {}", publish.topic);

                    match parse_dxl_message(&publish.payload) {
                        Ok(msg) => {
                            info!(
                                "Decoded DXL Message: ID={} Type={}",
                                msg.message_id, msg.message_type
                            );

                            // Normalise and Detect
                            if let Some(ocsf_event) =
                                handle_dxl_message(&publish.topic, &msg, &detection_engine)
                            {
                                dispatch_record(
                                    &cli,
                                    ocsf_event,
                                    Kind::Event,
                                    &syslog_tx,
                                    &http_tx,
                                    &kafka_tx,
                                )
                                .await;
                            }

                            // Feed into Detection Engine (use Value::Null when payload is empty or non-JSON)
                            let payload_json = std::str::from_utf8(&msg.payload)
                                .ok()
                                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());

                            if msg.message_type == dxl::MESSAGE_TYPE_RESPONSE
                                && msg.request_message_id.as_ref() == Some(&svc_query_msg_id)
                            {
                                if let Some(value) = &payload_json {
                                    detection_engine.process_sync_response(value);
                                    info!(
                                        "Processed svcregistry/query sync response. Loaded {} services.",
                                        detection_engine.services.len()
                                    );
                                }
                            } else if msg.message_type == dxl::MESSAGE_TYPE_RESPONSE
                                && msg.request_message_id.as_ref() == Some(&broker_query_msg_id)
                            {
                                if let Some(value) = &payload_json {
                                    detection_engine.process_broker_sync_response(value);
                                    info!(
                                        "Processed brokerregistry/query sync response. Loaded {} brokers.",
                                        detection_engine.brokers.len()
                                    );
                                }
                            } else if publish.topic == reply_to_topic {
                                if msg.message_type == dxl::MESSAGE_TYPE_ERROR {
                                    error!(
                                        "Received error response on reply topic (code={:?}): {:?}",
                                        msg.error_code, msg.error_message
                                    );
                                }
                            } else {
                                let value = payload_json.unwrap_or(serde_json::Value::Null);
                                let publisher_id = msg
                                    .other_fields
                                    .get("dxl.certs")
                                    .and_then(|certs| {
                                        certs.split(';').map(str::trim).rfind(|s| !s.is_empty())
                                    })
                                    .unwrap_or(&msg.source_client_id);
                                let alerts = detection_engine.process_event(
                                    &publish.topic,
                                    &value,
                                    publisher_id,
                                );
                                for alert in alerts {
                                    dispatch_record(
                                        &cli,
                                        alert,
                                        Kind::Detection,
                                        &syslog_tx,
                                        &http_tx,
                                        &kafka_tx,
                                    )
                                    .await;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to decode DXL message: {}", e);
                        }
                    }
                }
                _ => {}
            },
            Ok(Err(e)) => {
                let err_str = format!("{:?}", e);
                if err_str.contains("PeerIncompatible(ServerTlsVersionIsDisabledByOurConfig)") {
                    error!(
                        "Broker offers no TLS >= {}; lower TlsMinVersion or upgrade the broker",
                        config.tls_min_version
                    );
                } else {
                    error!("MQTT Connection error: {}", e);
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            Err(_) => {
                // Timeout, do periodic detection poll
            }
        }

        // Periodic check for timeouts (e.g. TTL expiry)
        let now = Utc::now().timestamp();
        if now - last_poll > 10 {
            let alerts = detection_engine.poll_timeouts();
            for alert in alerts {
                dispatch_record(
                    &cli,
                    alert,
                    Kind::Detection,
                    &syslog_tx,
                    &http_tx,
                    &kafka_tx,
                )
                .await;
            }
            last_poll = now;
        }
    }
}

async fn select_broker_endpoint(
    brokers: &[config::Broker],
    verify_hostname: bool,
) -> (String, u16) {
    let mut candidates: Vec<(String, u16)> = Vec::new();
    for b in brokers {
        let primary = if verify_hostname { &b.host } else { &b.ip };
        let secondary = if verify_hostname { &b.ip } else { &b.host };
        for raw in [primary, secondary] {
            let clean = raw.trim().trim_start_matches('[').trim_end_matches(']');
            if !clean.is_empty() {
                let pair = (clean.to_string(), b.port);
                if !candidates.contains(&pair) {
                    candidates.push(pair);
                }
            }
        }
    }
    if candidates.len() <= 1 {
        return candidates
            .into_iter()
            .next()
            .unwrap_or_else(|| ("127.0.0.1".to_string(), 8883));
    }
    for (host, port) in &candidates {
        if let Ok(Ok(_)) = tokio::time::timeout(
            Duration::from_millis(1500),
            tokio::net::TcpStream::connect((host.as_str(), *port)),
        )
        .await
        {
            info!("Selected reachable broker {}:{}", host, port);
            return (host.clone(), *port);
        }
    }
    candidates.into_iter().next().unwrap()
}

async fn subscribe_and_sync(
    client: &AsyncClient,
    config: &DxlConfig,
    reply_to_topic: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    client.subscribe(reply_to_topic, QoS::AtMostOnce).await?;
    info!("Subscribed to reply topic: {}", reply_to_topic);

    client
        .subscribe("/mcafee/event/dxl/#", QoS::AtMostOnce)
        .await?;
    for topic in &config.sensitive_topics {
        if !topic.is_empty() && !topic.starts_with("/mcafee/event/dxl/") {
            client.subscribe(topic, QoS::AtMostOnce).await?;
            info!("Subscribed to sensitive topic: {}", topic);
        }
    }

    let svc_query_msg_id = Uuid::new_v4().to_string();
    let svc_query_msg = DxlMessage {
        version: 3,
        message_type: MESSAGE_TYPE_REQUEST,
        message_id: svc_query_msg_id.clone(),
        source_client_id: config.client_id.clone(),
        source_broker_id: "".to_string(),
        broker_ids: vec![],
        client_ids: vec![],
        payload: b"{}".to_vec(),
        reply_to_topic: Some(reply_to_topic.to_string()),
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
    client
        .publish(
            "/mcafee/service/dxl/svcregistry/query",
            QoS::AtMostOnce,
            false,
            encoded_svc_query,
        )
        .await?;
    info!("Sent svcregistry/query");

    let broker_query_msg_id = Uuid::new_v4().to_string();
    let broker_query_msg = DxlMessage {
        message_id: broker_query_msg_id.clone(),
        ..svc_query_msg
    };
    let encoded_broker_query = encode_dxl_message(&broker_query_msg)?;
    client
        .publish(
            "/mcafee/service/dxl/brokerregistry/query",
            QoS::AtMostOnce,
            false,
            encoded_broker_query,
        )
        .await?;
    info!("Sent brokerregistry/query");

    Ok((svc_query_msg_id, broker_query_msg_id))
}

async fn dispatch_record(
    cli: &Cli,
    record: OcsfEvent,
    kind: Kind,
    syslog_tx: &Option<tokio::sync::mpsc::Sender<String>>,
    http_tx: &Option<tokio::sync::mpsc::Sender<OcsfEvent>>,
    kafka_tx: &Option<tokio::sync::mpsc::Sender<OcsfEvent>>,
) {
    let cef_str = format_cef(&record);
    emit(cli, &record, &cef_str, kind);
    if let Some(tx) = syslog_tx {
        let _ = tx.send(cef_str).await;
    }
    if let Some(tx) = http_tx {
        let _ = tx.send(record.clone()).await;
    }
    if let Some(tx) = kafka_tx {
        let _ = tx.send(record).await;
    }
}

/// Writes one record to stdout in the requested shape, or nothing when the
/// record is filtered out.
///
/// stdout carries records and nothing else - the prefixes this used to print
/// made the stream unusable in a pipe. Every line is flushed, because a sensor
/// that buffers is a sensor whose last line arrives after the incident.
fn emit(cli: &Cli, event: &OcsfEvent, cef: &str, kind: Kind) {
    if !cli.wants(kind) {
        return;
    }
    let line = match cli.format {
        Format::Cef => cef.to_string(),
        Format::Json => match serde_json::to_string(event) {
            Ok(json) => json,
            Err(e) => {
                error!("Could not serialise record: {}", e);
                return;
            }
        },
        Format::Plain => plain(event, kind),
    };
    let mut out = std::io::stdout().lock();
    if writeln!(out, "{line}").is_err() || out.flush().is_err() {
        // A closed stdout is how `| head` ends: leave quietly rather than
        // filling stderr with broken-pipe noise for every later record.
        std::process::exit(0);
    }
}

/// Human readable one-liner: when, how bad, what, and who it was about.
fn plain(event: &OcsfEvent, kind: Kind) -> String {
    let when = Utc
        .timestamp_millis_opt(event.time())
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "------ --:--:--".to_string());
    let marker = match kind {
        Kind::Detection => "!",
        Kind::Event => " ",
    };
    let who = event.principal().unwrap_or("-");
    format!(
        "{when} {marker} {:<13} {:<34} {who}",
        event.severity(),
        event.event_name()
    )
}

fn handle_dxl_message(
    topic: &str,
    msg: &DxlMessage,
    engine: &DetectionEngine,
) -> Option<OcsfEvent> {
    if let Ok(json_str) = std::str::from_utf8(&msg.payload)
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str)
    {
        let now = Utc::now().timestamp_millis();
        let metadata = OcsfMetadata::default();

        if topic.contains("clientregistry/connect") || topic.contains("clientregistry/disconnect") {
            let is_connect = topic.ends_with("/connect");
            let raw_client_guid = value
                .get("clientGuid")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let parts: Vec<&str> = raw_client_guid.split(':').collect();
            let client_guid = parts[0].to_string();
            let client_instance_guid = if parts.len() > 1 {
                Some(parts[1].to_string())
            } else {
                None
            };

            let mut src_endpoint = None;
            if let Some(ip) = value.get("remoteAddress").and_then(|v| v.as_str()) {
                let clean_ip = ip.strip_prefix("::ffff:").unwrap_or(ip);
                src_endpoint = Some(crate::ocsf::OcsfEndpoint {
                    uid: None,
                    ip: Some(clean_ip.to_string()),
                });
            }

            let tls_ver = value.get("tlsVersion").and_then(|v| v.as_str());
            let tls_cipher = value.get("cipher").and_then(|v| v.as_str());
            let cert_thumb = value.get("certThumbprint").and_then(|v| v.as_str());
            let tls = if tls_ver.is_some() || tls_cipher.is_some() || cert_thumb.is_some() {
                Some(crate::ocsf::OcsfTls {
                    version: tls_ver.unwrap_or_default().to_string(),
                    cipher_suites: tls_cipher.map(|c| vec![c.to_string()]).unwrap_or_default(),
                    certificate: cert_thumb.map(|f| crate::ocsf::OcsfCertificate {
                        fingerprint: f.to_string(),
                    }),
                })
            } else {
                None
            };

            let mut connection_info = None;
            if let Some(proto) = value.get("protocol").and_then(|v| v.as_str()) {
                connection_info = Some(crate::ocsf::OcsfConnectionInfo {
                    protocol_name: proto.to_string(),
                });
            }

            let na = NetworkActivity {
                activity_id: if is_connect { 1 } else { 2 },
                activity_name: if is_connect {
                    "Connect".to_string()
                } else {
                    "Disconnect".to_string()
                },
                category_uid: 4,
                category_name: "Network Activity".to_string(),
                class_uid: 4001,
                class_name: "Network Activity".to_string(),
                severity_id: 1,
                severity: "Informational".to_string(),
                time: now,
                type_uid: if is_connect { 400101 } else { 400102 },
                type_name: if is_connect {
                    "Network Connect".to_string()
                } else {
                    "Network Disconnect".to_string()
                },
                metadata,
                src_endpoint,
                tls,
                connection_info,
                client_guid,
                client_instance_guid,
            };
            return Some(OcsfEvent::NetworkActivity(na));
        } else if topic.contains("svcregistry/register") || topic.contains("svcregistry/unregister")
        {
            let is_register = topic.ends_with("/register");
            let service_guid = value
                .get("serviceGuid")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let service_type = if is_register {
                value
                    .get("serviceType")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                engine
                    .get_service_name(service_guid)
                    .unwrap_or_else(|| "unknown".to_string())
            };
            let client_guid = value.get("clientGuid").and_then(|v| v.as_str());

            let actor = client_guid.map(|guid| OcsfActor {
                user: OcsfUser {
                    uid: guid.to_string(),
                },
            });

            let aa = ApiActivity {
                activity_id: if is_register { 1 } else { 4 },
                activity_name: if is_register {
                    "Register Service".to_string()
                } else {
                    "Unregister Service".to_string()
                },
                category_uid: 6,
                category_name: "Application Activity".to_string(),
                class_uid: 6003,
                class_name: "API Activity".to_string(),
                severity_id: 1,
                severity: "Informational".to_string(),
                time: now,
                type_uid: if is_register { 600301 } else { 600304 },
                type_name: if is_register {
                    "Create API Activity".to_string()
                } else {
                    "Delete API Activity".to_string()
                },
                metadata,
                api: OcsfApi {
                    operation: if is_register {
                        "register".to_string()
                    } else {
                        "unregister".to_string()
                    },
                    service: OcsfService {
                        name: service_type.to_string(),
                        uid: service_guid.to_string(),
                    },
                },
                actor,
            };
            return Some(OcsfEvent::ApiActivity(aa));
        } else if !topic.starts_with("/mcafee/client/") {
            info!("Ignored event on topic {}", topic);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_dxl_message(payload: &[u8]) -> DxlMessage {
        DxlMessage {
            version: 3,
            message_type: dxl::MESSAGE_TYPE_EVENT,
            message_id: "{00000000-0000-0000-0000-000000000001}".to_string(),
            source_client_id: "5a752ed6a24f6d2dd77634b0c68dd729b48d4613".to_string(),
            source_broker_id: "{broker-1}".to_string(),
            broker_ids: vec![],
            client_ids: vec![],
            payload: payload.to_vec(),
            reply_to_topic: None,
            service_id: None,
            request_message_id: None,
            error_code: None,
            error_message: None,
            other_fields: HashMap::new(),
            source_tenant_guid: None,
            destination_tenant_guids: vec![],
            source_client_instance_id: None,
        }
    }

    #[test]
    fn register_and_unregister_events_use_matching_ocsf_activity_id_and_type_uid() {
        let engine = DetectionEngine::new(&DxlConfig::default());
        let reg_msg = sample_dxl_message(
            br#"{"serviceGuid":"{svc-1}","serviceType":"/mcafee/service/tie","clientGuid":"5a752ed6a24f6d2dd77634b0c68dd729b48d4613"}"#,
        );
        let event = handle_dxl_message("/mcafee/event/dxl/svcregistry/register", &reg_msg, &engine)
            .expect("register event must normalize");
        match event {
            OcsfEvent::ApiActivity(aa) => {
                assert_eq!(aa.activity_id, 1);
                assert_eq!(aa.type_uid, 600301);
                assert_eq!(aa.api.operation, "register");
            }
            other => panic!("expected ApiActivity, got {other:?}"),
        }

        let unreg_msg = sample_dxl_message(br#"{"serviceGuid":"{svc-1}"}"#);
        let event = handle_dxl_message(
            "/mcafee/event/dxl/svcregistry/unregister",
            &unreg_msg,
            &engine,
        )
        .expect("unregister event must normalize");
        match event {
            OcsfEvent::ApiActivity(aa) => {
                assert_eq!(aa.activity_id, 4);
                assert_eq!(aa.type_uid, 600304);
                assert_eq!(aa.api.operation, "unregister");
            }
            other => panic!("expected ApiActivity, got {other:?}"),
        }
    }
}
