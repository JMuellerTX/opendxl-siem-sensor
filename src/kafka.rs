use crate::config::DxlConfig;
use crate::ocsf::OcsfEvent;
#[cfg(not(feature = "rdkafka"))]
use log::error;
#[cfg(feature = "rdkafka")]
use log::{error, info};
use tokio::sync::mpsc;

#[cfg(feature = "rdkafka")]
use rdkafka::producer::{FutureProducer, FutureRecord};
#[cfg(feature = "rdkafka")]
use rdkafka::ClientConfig;
#[cfg(feature = "rdkafka")]
use std::time::Duration;

#[cfg(feature = "rdkafka")]
pub async fn start_kafka_sender(config: &DxlConfig) -> Option<mpsc::Sender<OcsfEvent>> {
    let brokers = config.kafka_brokers.clone()?;
    let topic = config.kafka_topic.clone().unwrap_or_else(|| "opendxl-events".to_string());
    
    let (tx, mut rx) = mpsc::channel::<OcsfEvent>(1000);
    
    info!("Starting Kafka sender to brokers {} on topic {}", brokers, topic);
    
    let producer: FutureProducer = match ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("message.timeout.ms", "5000")
        .create() {
            Ok(p) => p,
            Err(e) => {
                error!("Failed to create Kafka producer: {}", e);
                return None;
            }
        };

    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let Ok(json_str) = serde_json::to_string(&event) {
                let record = FutureRecord::to(&topic)
                    .payload(&json_str)
                    .key("opendxl-siem-sensor");
                
                if let Err((e, _)) = producer.send(record, Duration::from_secs(0)).await {
                    error!("Failed to send to Kafka: {:?}", e);
                }
            }
        }
    });

    Some(tx)
}

#[cfg(not(feature = "rdkafka"))]
pub async fn start_kafka_sender(config: &DxlConfig) -> Option<mpsc::Sender<OcsfEvent>> {
    if config.kafka_brokers.is_some() {
        error!("Kafka brokers configured, but 'rdkafka' feature was not enabled at compile time.");
    }
    None
}
