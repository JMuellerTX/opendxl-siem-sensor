use crate::config::DxlConfig;
use crate::ocsf::{DetectionFinding, OcsfEvent, OcsfFindingInfo, OcsfMetadata};
use chrono::Utc;
use std::collections::{HashMap, VecDeque};

pub struct DetectionEngine {
    grace_period_mins: u32,
    allowed_thumbprints: Vec<String>,
    sensitive_topics: Vec<String>,
    pub services: HashMap<String, ServiceState>,
    client_rates: HashMap<String, VecDeque<i64>>,
    topic_rates: HashMap<String, VecDeque<i64>>,
    pub brokers: HashMap<String, serde_json::Value>,
}

pub struct ServiceState {
    guid: String,
    service_type: String,
    registration_time_secs: i64,
    ttl_mins: u32,
    reported: bool,
}

impl DetectionEngine {
    pub fn new(config: &DxlConfig) -> Self {
        Self {
            grace_period_mins: config.service_ttl_grace_period_mins,
            allowed_thumbprints: config.allowed_thumbprints.clone(),
            sensitive_topics: config.sensitive_topics.clone(),
            services: HashMap::new(),
            client_rates: HashMap::new(),
            topic_rates: HashMap::new(),
            brokers: HashMap::new(),
        }
    }

    pub fn process_event(&mut self, topic: &str, payload: &serde_json::Value, source_client_id: &str) -> Vec<OcsfEvent> {
        let mut alerts = Vec::new();
        let now = Utc::now().timestamp_millis();
        let metadata = OcsfMetadata::default();

        // (b) Unknown Thumbprint
        if topic.ends_with("/register") {
            if let Some(certs) = payload.get("certificates").and_then(|v| v.as_array())
                && !self.allowed_thumbprints.is_empty() {
                    for cert in certs {
                        if let Some(cert_str) = cert.as_str()
                            && !self.allowed_thumbprints.contains(&cert_str.to_string()) {
                                alerts.push(Self::build_detection(
                                    now,
                                    &metadata,
                                    "Unknown Certificate Thumbprint",
                                    &format!("Service registered with unknown thumbprint: {}", cert_str),
                                ));
                            }
                    }
                }

            // Track for TTL (a)
            if let (Some(guid), Some(svc_type), Some(ttl), Some(reg_time)) = (
                payload.get("serviceGuid").and_then(|v| v.as_str()),
                payload.get("serviceType").and_then(|v| v.as_str()),
                payload.get("ttlMins").and_then(|v| v.as_u64()),
                payload.get("registrationTime").and_then(|v| v.as_i64()),
            ) {
                self.services.insert(guid.to_string(), ServiceState {
                    guid: guid.to_string(),
                    service_type: svc_type.to_string(),
                    registration_time_secs: reg_time,
                    ttl_mins: ttl as u32,
                    reported: false,
                });
            }
        } else if topic.ends_with("/unregister")
            && let Some(guid) = payload.get("serviceGuid").and_then(|v| v.as_str()) {
                self.services.remove(guid);
            }

        // (c) Sensitive Topic Publisher
        for sensitive_topic in &self.sensitive_topics {
            // Very naive glob matching logic for topics
            if topic == sensitive_topic || (sensitive_topic.ends_with("/#") && topic.starts_with(&sensitive_topic[..sensitive_topic.len() - 1])) {
                alerts.push(Self::build_detection(
                    now,
                    &metadata,
                    "Sensitive Topic Published",
                    &format!("Client {} published to sensitive topic {}", source_client_id, topic),
                ));
            }
        }

        // (d) Rate/Size Anomaly (Simplified to simple count rate over 60s window)
        Self::track_rate(&mut self.client_rates, source_client_id, now, &mut alerts, &metadata, "Client Rate Anomaly");
        Self::track_rate(&mut self.topic_rates, topic, now, &mut alerts, &metadata, "Topic Rate Anomaly");

        // (e) Fabric Change
        if topic.contains("fabricchange") || topic.contains("brokerregistry/brokerstate") {
            // Simplified check: usually we'd parse the bridge states
            // Here we just alert that a fabric change occurred, which could indicate a bridge up/down
            alerts.push(Self::build_detection(
                now,
                &metadata,
                "Fabric Change Detected",
                "A fabric topology change or broker state change was detected.",
            ));
        }

        alerts
    }

    pub fn poll_timeouts(&mut self) -> Vec<OcsfEvent> {
        self.poll_timeouts_at(Utc::now().timestamp())
    }

    pub fn poll_timeouts_at(&mut self, now_secs: i64) -> Vec<OcsfEvent> {
        let mut alerts = Vec::new();
        let now_ms = now_secs * 1000;
        let metadata = OcsfMetadata::default();

        for state in self.services.values_mut() {
            if !state.reported {
                let expiry = state.registration_time_secs + (state.ttl_mins as i64 * 60) + (self.grace_period_mins as i64 * 60);
                if now_secs > expiry {
                    alerts.push(Self::build_detection(
                        now_ms,
                        &metadata,
                        "Service TTL Expired",
                        &format!("Service {} ({}) TTL expired without unregister", state.guid, state.service_type),
                    ));
                    state.reported = true;
                }
            }
        }
        alerts
    }

    fn track_rate(rates: &mut HashMap<String, VecDeque<i64>>, key: &str, now: i64, alerts: &mut Vec<OcsfEvent>, metadata: &OcsfMetadata, title: &str) {
        let entry = rates.entry(key.to_string()).or_default();
        entry.push_back(now);
        // Remove older than 60 seconds
        while let Some(&t) = entry.front() {
            if now - t > 60_000 {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() > 100 { // Threshold: 100 msgs/min
            alerts.push(Self::build_detection(
                now,
                metadata,
                title,
                &format!("High rate detected for {}", key),
            ));
            entry.clear(); // Debounce
        }
    }

    fn build_detection(time: i64, metadata: &OcsfMetadata, title: &str, desc: &str) -> OcsfEvent {
        OcsfEvent::DetectionFinding(DetectionFinding {
            activity_id: 1,
            activity_name: "Create".to_string(),
            category_uid: 2,
            category_name: "Findings".to_string(),
            class_uid: 2004,
            class_name: "Detection Finding".to_string(),
            severity_id: 4, // High severity for detections by default
            severity: "High".to_string(),
            time,
            type_uid: 200401,
            type_name: "Create Detection".to_string(),
            metadata: metadata.clone(),
            finding_info: OcsfFindingInfo {
                title: title.to_string(),
                desc: desc.to_string(),
            },
        })
    }

    pub fn get_service_name(&self, guid: &str) -> Option<String> {
        self.services.get(guid).map(|s| s.service_type.clone())
    }

    pub fn process_sync_response(&mut self, payload: &serde_json::Value) {
        if let Some(services) = payload.get("services").and_then(|v| v.as_object()) {
            for (guid, svc_info) in services {
                if let (Some(svc_type), Some(ttl), Some(reg_time)) = (
                    svc_info.get("serviceType").and_then(|v| v.as_str()),
                    svc_info.get("ttlMins").and_then(|v| v.as_u64()),
                    svc_info.get("registrationTime").and_then(|v| v.as_i64()),
                ) {
                    self.services.insert(guid.to_string(), ServiceState {
                        guid: guid.to_string(),
                        service_type: svc_type.to_string(),
                        registration_time_secs: reg_time,
                        ttl_mins: ttl as u32,
                        reported: false,
                    });
                }
            }
        }
    }

    pub fn process_broker_sync_response(&mut self, payload: &serde_json::Value) {
        if let Some(brokers) = payload.get("brokers").and_then(|v| v.as_object()) {
            for (guid, broker_info) in brokers {
                self.brokers.insert(guid.to_string(), broker_info.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_config() -> DxlConfig {
        DxlConfig {
            service_ttl_grace_period_mins: 5,
            allowed_thumbprints: vec!["allowed_hash".to_string()],
            sensitive_topics: vec!["/mcafee/service/tie/file/reputation".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn test_ttl_expiry() {
        let mut engine = DetectionEngine::new(&test_config());
        let now_secs = Utc::now().timestamp();
        
        let payload = json!({
            "serviceGuid": "test-guid",
            "serviceType": "/test/service",
            "ttlMins": 10,
            "registrationTime": now_secs - 1000 // Expired > (10 + 5) * 60 = 900
        });

        engine.process_event("/mcafee/event/dxl/svcregistry/register", &payload, "client-id");
        
        let alerts = engine.poll_timeouts();
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Service TTL Expired");
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_thumbprint_anomaly() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({
            "serviceGuid": "test-guid",
            "serviceType": "/test/service",
            "certificates": ["unknown_hash"],
            "ttlMins": 10,
            "registrationTime": Utc::now().timestamp()
        });

        let alerts = engine.process_event("/mcafee/event/dxl/svcregistry/register", &payload, "client-id");
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn test_empty_allowlist_no_anomaly() {
        let mut config = test_config();
        config.allowed_thumbprints.clear(); // Empty allowlist
        let mut engine = DetectionEngine::new(&config);
        let payload = json!({
            "serviceGuid": "test-guid",
            "serviceType": "/test/service",
            "certificates": ["unknown_hash"],
        });

        let alerts = engine.process_event("/mcafee/event/dxl/svcregistry/register", &payload, "client-id");
        assert_eq!(alerts.len(), 0); // Should be empty since allowlist is empty
    }

    #[test]
    fn test_sensitive_topic() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({});
        let alerts = engine.process_event("/mcafee/service/tie/file/reputation", &payload, "client-id");
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Sensitive Topic Published");
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_rate_anomaly() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({});
        let mut alerts = Vec::new();
        // Send 101 events in quick succession
        for _ in 0..101 {
            let res = engine.process_event("/some/normal/topic", &payload, "client-id");
            alerts.extend(res);
        }
        // At 101st event, rate anomaly should trigger for client and topic
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn test_fabric_change() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({});
        let alerts = engine.process_event("/mcafee/event/dxl/fabricchange", &payload, "client-id");
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Fabric Change Detected");
        } else {
            panic!("Expected DetectionFinding");
        }
    }
}
