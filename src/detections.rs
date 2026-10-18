use crate::config::DxlConfig;
use crate::ocsf::{DetectionFinding, OcsfEvent, OcsfFindingInfo, OcsfMetadata};
use chrono::Utc;
use std::collections::{HashMap, HashSet, VecDeque};

fn normalize_thumbprint(thumb: &str) -> String {
    thumb.trim().replace(':', "").to_ascii_lowercase()
}

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
            allowed_thumbprints: config
                .allowed_thumbprints
                .iter()
                .map(|s| normalize_thumbprint(s))
                .filter(|s| !s.is_empty())
                .collect(),
            sensitive_topics: config.sensitive_topics.clone(),
            services: HashMap::new(),
            client_rates: HashMap::new(),
            topic_rates: HashMap::new(),
            brokers: HashMap::new(),
        }
    }

    pub fn process_event(
        &mut self,
        topic: &str,
        payload: &serde_json::Value,
        source_client_id: &str,
    ) -> Vec<OcsfEvent> {
        let mut alerts = Vec::new();
        let now = Utc::now().timestamp_millis();
        let metadata = OcsfMetadata::default();

        // (b) Unknown Thumbprint
        if !self.allowed_thumbprints.is_empty() {
            // Check Connect events
            if topic.ends_with("/connect")
                && let Some(cert_str) = payload
                    .get("certThumbprint")
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        payload
                            .get("clientGuid")
                            .and_then(|v| v.as_str())
                            .map(|g| g.split(':').next().unwrap_or(g))
                    })
            {
                let norm = normalize_thumbprint(cert_str);
                if !norm.is_empty() && !self.allowed_thumbprints.contains(&norm) {
                    alerts.push(Self::build_detection(
                        now,
                        &metadata,
                        "Unknown Certificate Thumbprint",
                        &format!("Client connected with unknown thumbprint: {}", cert_str),
                        Some(cert_str.to_string()),
                    ));
                }
            }

            // Check publishers on non-broker topics (broker events under
            // /mcafee/event/dxl/ carry the broker's GUID as source_client_id;
            // client connect and service register events are checked above/below).
            if !topic.starts_with("/mcafee/event/dxl/")
                && !self.brokers.contains_key(source_client_id)
                && !source_client_id.is_empty()
            {
                let norm = normalize_thumbprint(source_client_id);
                if !norm.is_empty() && !self.allowed_thumbprints.contains(&norm) {
                    alerts.push(Self::build_detection(
                        now,
                        &metadata,
                        "Unknown Certificate Thumbprint",
                        &format!("Publisher with unknown thumbprint: {}", source_client_id),
                        Some(source_client_id.to_string()),
                    ));
                }
            }

            if topic.ends_with("/register")
                && let Some(certs) = payload.get("certificates").and_then(|v| v.as_array())
            {
                for cert in certs {
                    if let Some(cert_str) = cert.as_str() {
                        let norm = normalize_thumbprint(cert_str);
                        if !norm.is_empty() && !self.allowed_thumbprints.contains(&norm) {
                            alerts.push(Self::build_detection(
                                now,
                                &metadata,
                                "Unknown Certificate Thumbprint",
                                &format!(
                                    "Service registered with unknown thumbprint: {}",
                                    cert_str
                                ),
                                Some(cert_str.to_string()),
                            ));
                        }
                    }
                }
            }
        }

        // (f) Legacy Cipher Suite
        if topic.ends_with("/connect")
            && let Some(cipher) = payload.get("cipher").and_then(|v| v.as_str())
            && cipher.starts_with("TLS_RSA_")
            && !cipher.contains("ECDHE")
        {
            let thumbprint = payload
                .get("certThumbprint")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    payload
                        .get("clientGuid")
                        .and_then(|v| v.as_str())
                        .map(|g| g.split(':').next().unwrap_or(g))
                });
            alerts.push(Self::build_detection(
                now,
                &metadata,
                "Legacy Cipher Suite",
                &format!("Client connected with weak legacy cipher: {}", cipher),
                thumbprint.map(|s| s.to_string()),
            ));
        }

        // Track for TTL (a)
        if topic.ends_with("/register") {
            if let (Some(guid), Some(svc_type), Some(ttl), Some(reg_time)) = (
                payload.get("serviceGuid").and_then(|v| v.as_str()),
                payload.get("serviceType").and_then(|v| v.as_str()),
                payload.get("ttlMins").and_then(|v| v.as_u64()),
                payload.get("registrationTime").and_then(|v| v.as_i64()),
            ) {
                self.services.insert(
                    guid.to_string(),
                    ServiceState {
                        guid: guid.to_string(),
                        service_type: svc_type.to_string(),
                        registration_time_secs: reg_time,
                        ttl_mins: ttl as u32,
                        reported: false,
                    },
                );
            }
        } else if topic.ends_with("/unregister")
            && let Some(guid) = payload.get("serviceGuid").and_then(|v| v.as_str())
            && let Some(state) = self.services.remove(guid)
        {
            // When the broker's own TTL Reaper unregisters an expired service,
            // it fires svcregistry/unregister right at (ttlMins + grace) * 60.
            // Check whether the service was already past its TTL+grace window
            // so the broker event does not preempt poll_timeouts().
            let now_secs = now / 1000;
            let expiry = state.registration_time_secs
                + (state.ttl_mins as i64 * 60)
                + (self.grace_period_mins as i64 * 60);
            if !state.reported && now_secs >= expiry {
                alerts.push(Self::build_detection(
                    now,
                    &metadata,
                    "Service TTL Expired",
                    &format!(
                        "Service {} ({}) TTL expired without unregister",
                        state.guid, state.service_type
                    ),
                    None,
                ));
            }
        }

        // (c) Sensitive Topic Publisher
        for sensitive_topic in &self.sensitive_topics {
            if topic_matches(sensitive_topic, topic) {
                alerts.push(Self::build_detection(
                    now,
                    &metadata,
                    "Sensitive Topic Published",
                    &format!(
                        "Client {} published to sensitive topic {}",
                        source_client_id, topic
                    ),
                    Some(source_client_id.to_string()),
                ));
            }
        }

        // (d) Rate/Size Anomaly (Simplified to simple count rate over 60s window)
        Self::track_rate(
            &mut self.client_rates,
            source_client_id,
            now,
            &mut alerts,
            &metadata,
            "Client Rate Anomaly",
        );
        Self::track_rate(
            &mut self.topic_rates,
            topic,
            now,
            &mut alerts,
            &metadata,
            "Topic Rate Anomaly",
        );

        // (e) Fabric Change
        if topic.contains("fabricchange") {
            alerts.push(Self::build_detection(
                now,
                &metadata,
                "Fabric Change Detected",
                "A fabric topology change or broker state change was detected.",
                None,
            ));
        } else if topic.contains("brokerregistry/brokerstate") {
            let changed = if let Some(guid) = payload.get("guid").and_then(|v| v.as_str()) {
                let prev = self.brokers.insert(guid.to_string(), payload.clone());
                match prev {
                    None => true,
                    Some(old) => {
                        old.get("bridges") != payload.get("bridges")
                            || old.get("startTime") != payload.get("startTime")
                    }
                }
            } else {
                true
            };
            if changed {
                alerts.push(Self::build_detection(
                    now,
                    &metadata,
                    "Fabric Change Detected",
                    "A fabric topology change or broker state change was detected.",
                    None,
                ));
            }
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

        for q in self.client_rates.values_mut() {
            while let Some(&t) = q.front() {
                if now_ms - t > 60_000 {
                    q.pop_front();
                } else {
                    break;
                }
            }
        }
        self.client_rates.retain(|_, q| !q.is_empty());

        for q in self.topic_rates.values_mut() {
            while let Some(&t) = q.front() {
                if now_ms - t > 60_000 {
                    q.pop_front();
                } else {
                    break;
                }
            }
        }
        self.topic_rates.retain(|_, q| !q.is_empty());

        for state in self.services.values_mut() {
            if !state.reported {
                let expiry = state.registration_time_secs
                    + (state.ttl_mins as i64 * 60)
                    + (self.grace_period_mins as i64 * 60);
                if now_secs > expiry {
                    alerts.push(Self::build_detection(
                        now_ms,
                        &metadata,
                        "Service TTL Expired",
                        &format!(
                            "Service {} ({}) TTL expired without unregister",
                            state.guid, state.service_type
                        ),
                        None,
                    ));
                    state.reported = true;
                }
            }
        }
        alerts
    }

    fn track_rate(
        rates: &mut HashMap<String, VecDeque<i64>>,
        key: &str,
        now: i64,
        alerts: &mut Vec<OcsfEvent>,
        metadata: &OcsfMetadata,
        title: &str,
    ) {
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
        if entry.len() > 100 {
            // Threshold: 100 msgs/min
            alerts.push(Self::build_detection(
                now,
                metadata,
                title,
                &format!("High rate detected for {}", key),
                None,
            ));
            entry.clear(); // Debounce
        }
    }

    fn build_detection(
        time: i64,
        metadata: &OcsfMetadata,
        title: &str,
        desc: &str,
        suser: Option<String>,
    ) -> OcsfEvent {
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
            suser,
        })
    }

    pub fn get_service_name(&self, guid: &str) -> Option<String> {
        self.services.get(guid).map(|s| s.service_type.clone())
    }

    pub fn process_sync_response(&mut self, payload: &serde_json::Value) -> Vec<OcsfEvent> {
        let mut alerts = Vec::new();
        let now = Utc::now().timestamp_millis();
        let metadata = OcsfMetadata::default();

        if let Some(services) = payload.get("services").and_then(|v| v.as_object()) {
            let mut seen = HashSet::new();
            for (guid, svc_info) in services {
                if let (Some(svc_type), Some(ttl), Some(reg_time)) = (
                    svc_info.get("serviceType").and_then(|v| v.as_str()),
                    svc_info.get("ttlMins").and_then(|v| v.as_u64()),
                    svc_info.get("registrationTime").and_then(|v| v.as_i64()),
                ) {
                    seen.insert(guid.to_string());
                    self.services.insert(
                        guid.to_string(),
                        ServiceState {
                            guid: guid.to_string(),
                            service_type: svc_type.to_string(),
                            registration_time_secs: reg_time,
                            ttl_mins: ttl as u32,
                            reported: false,
                        },
                    );
                }
                if !self.allowed_thumbprints.is_empty()
                    && let Some(certs) = svc_info.get("certificates").and_then(|v| v.as_array())
                {
                    for cert in certs {
                        if let Some(cert_str) = cert.as_str() {
                            let norm = normalize_thumbprint(cert_str);
                            if !norm.is_empty() && !self.allowed_thumbprints.contains(&norm) {
                                alerts.push(Self::build_detection(
                                    now,
                                    &metadata,
                                    "Unknown Certificate Thumbprint",
                                    &format!(
                                        "Service registered with unknown thumbprint: {}",
                                        cert_str
                                    ),
                                    Some(cert_str.to_string()),
                                ));
                            }
                        }
                    }
                }
            }
            self.services.retain(|k, _| seen.contains(k));
        }
        alerts
    }

    pub fn process_broker_sync_response(&mut self, payload: &serde_json::Value) {
        if let Some(brokers) = payload.get("brokers").and_then(|v| v.as_object()) {
            let mut seen = HashSet::new();
            for (guid, broker_info) in brokers {
                seen.insert(guid.to_string());
                self.brokers.insert(guid.to_string(), broker_info.clone());
            }
            self.brokers.retain(|k, _| seen.contains(k));
        }
    }
}

fn topic_matches(filter: &str, topic: &str) -> bool {
    if filter == "#" || filter == topic {
        return true;
    }
    let filter_levels: Vec<&str> = filter.split('/').collect();
    let topic_levels: Vec<&str> = topic.split('/').collect();

    for (i, f_level) in filter_levels.iter().enumerate() {
        if *f_level == "#" {
            return true;
        }
        let Some(t_level) = topic_levels.get(i) else {
            return false;
        };
        if *f_level != "+" && *f_level != *t_level {
            return false;
        }
        // If the next filter level is a trailing "#", and we matched up to the final topic level
        if i + 1 == topic_levels.len()
            && i + 2 == filter_levels.len()
            && filter_levels[i + 1] == "#"
        {
            return true;
        }
    }
    filter_levels.len() == topic_levels.len()
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

        engine.process_event(
            "/mcafee/event/dxl/svcregistry/register",
            &payload,
            "allowed_hash",
        );

        let alerts = engine.poll_timeouts();
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Service TTL Expired");
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_ttl_expiry_on_broker_unregister_event() {
        let mut engine = DetectionEngine::new(&test_config());
        let now_secs = Utc::now().timestamp();

        let reg_payload = json!({
            "serviceGuid": "expired-svc",
            "serviceType": "/test/expired",
            "ttlMins": 10,
            "registrationTime": now_secs - 905 // >= (10 + 5) * 60 = 900
        });
        engine.process_event(
            "/mcafee/event/dxl/svcregistry/register",
            &reg_payload,
            "{broker-guid}",
        );

        let unreg_payload = json!({ "serviceGuid": "expired-svc" });
        let alerts = engine.process_event(
            "/mcafee/event/dxl/svcregistry/unregister",
            &unreg_payload,
            "{broker-guid}",
        );
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Service TTL Expired");
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_broker_event_does_not_trigger_unknown_publisher_thumbprint_before_sync() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({
            "clientGuid": "allowed_hash:instance-1",
            "certThumbprint": "allowed_hash",
            "tlsVersion": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384"
        });
        // Even before brokerregistry/query populates engine.brokers, a broker event's
        // source_client_id ({broker-guid}) must not be flagged as an unknown client thumbprint.
        let alerts = engine.process_event(
            "/mcafee/event/dxl/clientregistry/connect",
            &payload,
            "{unseen-broker-guid}",
        );
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_brokerstate_updates_brokers_map_and_deduplicates_unchanged_state() {
        let mut engine = DetectionEngine::new(&test_config());
        let state = json!({
            "guid": "{broker-1}",
            "bridges": ["{broker-2}"],
            "startTime": 1700000000
        });
        let first = engine.process_event(
            "/mcafee/event/dxl/brokerregistry/brokerstate",
            &state,
            "{broker-1}",
        );
        assert_eq!(first.len(), 1);
        assert!(engine.brokers.contains_key("{broker-1}"));

        // Identical periodic heartbeat must not re-fire
        let second = engine.process_event(
            "/mcafee/event/dxl/brokerregistry/brokerstate",
            &state,
            "{broker-1}",
        );
        assert!(second.is_empty());
    }

    #[test]
    fn test_mqtt_topic_wildcards() {
        assert!(!topic_matches("/a/b/b/#", "/a/b"));
        assert!(topic_matches("/a/b/#", "/a/b"));
        assert!(topic_matches("/a/b/#", "/a/b/c"));
        assert!(topic_matches("/a/+/c", "/a/b/c"));
        assert!(topic_matches(
            "/mcafee/service/tie/#",
            "/mcafee/service/tie"
        ));
        assert!(topic_matches(
            "/mcafee/service/tie/#",
            "/mcafee/service/tie/file/reputation"
        ));
        assert!(topic_matches(
            "/mcafee/service/+/file/reputation",
            "/mcafee/service/tie/file/reputation"
        ));
        assert!(!topic_matches(
            "/mcafee/service/+/file/reputation",
            "/mcafee/service/tie/cert/reputation"
        ));
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

        let alerts = engine.process_event(
            "/mcafee/event/dxl/svcregistry/register",
            &payload,
            "allowed_hash",
        );
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

        let alerts = engine.process_event(
            "/mcafee/event/dxl/svcregistry/register",
            &payload,
            "client-id",
        );
        assert_eq!(alerts.len(), 0); // Should be empty since allowlist is empty
    }

    #[test]
    fn test_sensitive_topic() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({});
        let alerts = engine.process_event(
            "/mcafee/service/tie/file/reputation",
            &payload,
            "allowed_hash",
        );
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
            let res = engine.process_event("/some/normal/topic", &payload, "allowed_hash");
            alerts.extend(res);
        }
        // At 101st event, rate anomaly should trigger for client and topic
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn test_fabric_change() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({});
        let alerts =
            engine.process_event("/mcafee/event/dxl/fabricchange", &payload, "allowed_hash");
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Fabric Change Detected");
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_legacy_cipher_suite() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({
            "cipher": "TLS_RSA_WITH_AES_256_GCM_SHA384"
        });
        let alerts = engine.process_event(
            "/mcafee/event/dxl/clientregistry/connect",
            &payload,
            "allowed_hash",
        );
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Legacy Cipher Suite");
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_publisher_unknown_thumbprint() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({});
        // Publish to a normal topic with an unknown client id
        let alerts = engine.process_event("/some/normal/topic", &payload, "unknown_client");
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Unknown Certificate Thumbprint");
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_sync_response_prunes_stale_entries_and_checks_certificates() {
        let mut engine = DetectionEngine::new(&test_config());
        let now_secs = Utc::now().timestamp();

        let first_sync = json!({
            "services": {
                "svc-1": {
                    "serviceType": "/svc/one",
                    "ttlMins": 10,
                    "registrationTime": now_secs,
                    "certificates": ["ALLOWED_HASH"]
                },
                "svc-stale": {
                    "serviceType": "/svc/stale",
                    "ttlMins": 10,
                    "registrationTime": now_secs,
                    "certificates": ["allowed_hash"]
                }
            }
        });
        let alerts = engine.process_sync_response(&first_sync);
        assert!(alerts.is_empty());
        assert_eq!(engine.services.len(), 2);

        let second_sync = json!({
            "services": {
                "svc-1": {
                    "serviceType": "/svc/one",
                    "ttlMins": 10,
                    "registrationTime": now_secs,
                    "certificates": ["untrusted_sync_cert"]
                }
            }
        });
        let alerts = engine.process_sync_response(&second_sync);
        assert_eq!(engine.services.len(), 1);
        assert!(engine.services.contains_key("svc-1"));
        assert!(!engine.services.contains_key("svc-stale"));
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Unknown Certificate Thumbprint");
            assert_eq!(df.suser.as_deref(), Some("untrusted_sync_cert"));
        } else {
            panic!("Expected DetectionFinding");
        }

        engine.process_broker_sync_response(&json!({
            "brokers": {
                "{broker-1}": { "guid": "{broker-1}" },
                "{broker-stale}": { "guid": "{broker-stale}" }
            }
        }));
        assert_eq!(engine.brokers.len(), 2);

        engine.process_broker_sync_response(&json!({
            "brokers": {
                "{broker-1}": { "guid": "{broker-1}" }
            }
        }));
        assert_eq!(engine.brokers.len(), 1);
        assert!(engine.brokers.contains_key("{broker-1}"));
    }

    #[test]
    fn test_poll_timeouts_at_prunes_stale_rate_windows() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!({});
        engine.process_event("/some/normal/topic", &payload, "allowed_hash");
        assert_eq!(engine.client_rates.len(), 1);
        assert_eq!(engine.topic_rates.len(), 1);

        let future_secs = Utc::now().timestamp() + 65;
        let _ = engine.poll_timeouts_at(future_secs);
        assert!(engine.client_rates.is_empty());
        assert!(engine.topic_rates.is_empty());
    }
}
