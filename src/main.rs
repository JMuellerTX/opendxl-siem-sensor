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
    let Some(broker) = config.brokers.first() else {
        eprintln!(
            "Error: {} lists no brokers in its [Brokers] section.",
            config_path
        );
        std::process::exit(2);
    };

    // Exit code 2, the same as a configuration that cannot be read: a wrong
    // path or an unreadable certificate is a configuration problem, and the
    // message has to name the file. A panic here would print a backtrace to
    // someone who is looking at a provisioning directory, not at this source.
    let mut mqttoptions = build_mqtt_options(
        &config.client_id,
        &broker.ip,
        broker.port,
        &config.broker_cert_chain,
        &config.cert_file,
        &config.private_key,
        config.verify_hostname,
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
    client.subscribe(&reply_to_topic, QoS::AtMostOnce).await?;
    info!("Subscribed to reply topic: {}", reply_to_topic);

    client
        .subscribe("/mcafee/event/dxl/#", QoS::AtMostOnce)
        .await?;

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
        ..svc_query_msg.clone()
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

    let mut last_poll = Utc::now().timestamp();

    loop {
        // Use timeout to allow periodic polling for detections
        match tokio::time::timeout(Duration::from_secs(10), eventloop.poll()).await {
            Ok(Ok(notification)) => {
                if let rumqttc::Event::Incoming(rumqttc::Packet::Publish(publish)) = notification {
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
                                let cef_str = format_cef(&ocsf_event);
                                emit(&cli, &ocsf_event, &cef_str, Kind::Event);

                                if let Some(tx) = &syslog_tx {
                                    let _ = tx.send(cef_str).await;
                                }
                                if let Some(tx) = &http_tx {
                                    let _ = tx.send(ocsf_event.clone()).await;
                                }
                                if let Some(tx) = &kafka_tx {
                                    let _ = tx.send(ocsf_event).await;
                                }
                            }

                            // Feed into Detection Engine if payload is JSON
                            if let Ok(json_str) = std::str::from_utf8(&msg.payload)
                                && let Ok(value) =
                                    serde_json::from_str::<serde_json::Value>(json_str)
                            {
                                if msg.message_type == dxl::MESSAGE_TYPE_RESPONSE
                                    && msg.request_message_id.as_ref() == Some(&svc_query_msg_id)
                                {
                                    detection_engine.process_sync_response(&value);
                                    info!(
                                        "Processed svcregistry/query sync response. Loaded {} services.",
                                        detection_engine.services.len()
                                    );
                                } else if msg.message_type == dxl::MESSAGE_TYPE_RESPONSE
                                    && msg.request_message_id.as_ref() == Some(&broker_query_msg_id)
                                {
                                    detection_engine.process_broker_sync_response(&value);
                                    info!(
                                        "Processed brokerregistry/query sync response. Loaded {} brokers.",
                                        detection_engine.brokers.len()
                                    );
                                } else {
                                    let alerts = detection_engine.process_event(
                                        &publish.topic,
                                        &value,
                                        &msg.source_client_id,
                                    );
                                    for alert in alerts {
                                        let cef_str = format_cef(&alert);
                                        emit(&cli, &alert, &cef_str, Kind::Detection);
                                        if let Some(tx) = &syslog_tx {
                                            let _ = tx.send(cef_str).await;
                                        }
                                        if let Some(tx) = &http_tx {
                                            let _ = tx.send(alert.clone()).await;
                                        }
                                        if let Some(tx) = &kafka_tx {
                                            let _ = tx.send(alert).await;
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to decode DXL message: {}", e);
                        }
                    }
                }
            }
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
                let cef_str = format_cef(&alert);
                emit(&cli, &alert, &cef_str, Kind::Detection);
                if let Some(tx) = &syslog_tx {
                    let _ = tx.send(cef_str).await;
                }
                if let Some(tx) = &http_tx {
                    let _ = tx.send(alert.clone()).await;
                }
                if let Some(tx) = &kafka_tx {
                    let _ = tx.send(alert).await;
                }
            }
            last_poll = now;
        }
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

            let mut tls = None;
            if let (Some(ver), Some(cipher)) = (
                value.get("tlsVersion").and_then(|v| v.as_str()),
                value.get("cipher").and_then(|v| v.as_str()),
            ) {
                let cert = value
                    .get("certThumbprint")
                    .and_then(|v| v.as_str())
                    .map(|f| crate::ocsf::OcsfCertificate {
                        fingerprint: f.to_string(),
                    });
                tls = Some(crate::ocsf::OcsfTls {
                    version: ver.to_string(),
                    cipher_suites: vec![cipher.to_string()],
                    certificate: cert,
                });
            }

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
                activity_id: if is_register { 2 } else { 4 },
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
