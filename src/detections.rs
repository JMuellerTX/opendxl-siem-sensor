use crate::config::DxlConfig;
use crate::ocsf::{DetectionFinding, OcsfEvent, OcsfFindingInfo, OcsfMetadata};
use chrono::Utc;
use std::collections::{HashMap, HashSet, VecDeque};

fn normalize_thumbprint(thumb: &str) -> String {
    thumb.trim().replace(':', "").to_ascii_lowercase()
}

fn normalize_identity(id: &str) -> String {
    let head = id.trim().split(':').next().unwrap_or("");
    head.trim_start_matches('{')
        .trim_end_matches('}')
        .replace(':', "")
        .to_ascii_lowercase()
}

pub fn is_hex_thumbprint(id: &str) -> bool {
    let head = id.trim().split(':').next().unwrap_or("");
    head.len() == 40 && head.bytes().all(|b| b.is_ascii_hexdigit())
}

pub const TOPIC_CLIENT_CONNECT: &str = "/mcafee/event/dxl/clientregistry/connect";
pub const TOPIC_CLIENT_DISCONNECT: &str = "/mcafee/event/dxl/clientregistry/disconnect";
pub const TOPIC_SVC_REGISTER: &str = "/mcafee/event/dxl/svcregistry/register";
pub const TOPIC_SVC_UNREGISTER: &str = "/mcafee/event/dxl/svcregistry/unregister";
pub const TOPIC_FABRIC_CHANGE: &str = "/mcafee/event/dxl/fabricchange";
pub const TOPIC_BROKER_STATE: &str = "/mcafee/event/dxl/brokerregistry/brokerstate";
pub const TOPIC_REVOCATION_LIST: &str = "/mcafee/event/dxl/revocation/list";

const KNOWN_BROKER_EVENT_TOPICS: &[&str] = &[
    TOPIC_CLIENT_CONNECT,
    TOPIC_CLIENT_DISCONNECT,
    TOPIC_SVC_REGISTER,
    TOPIC_SVC_UNREGISTER,
    TOPIC_FABRIC_CHANGE,
    TOPIC_BROKER_STATE,
    TOPIC_REVOCATION_LIST,
    "/mcafee/event/dxl/brokerregistry/brokerstatetopics",
    "/mcafee/event/dxl/brokerregistry/topicadded",
    "/mcafee/event/dxl/brokerregistry/topicremoved",
    "/mcafee/event/dxl/eventsubscribernotfound",
    "/mcafee/event/dxl/dumpbrokerstate",
    "/mcafee/event/dxl/dumpservicestate",
    "/mcafee/event/dxl/tenant/limit/exceeded",
    "/mcafee/event/dxl/tenant/limit/reset",
];

pub fn is_known_broker_event_topic(topic: &str) -> bool {
    KNOWN_BROKER_EVENT_TOPICS.contains(&topic)
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
    client_guid: Option<String>,
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

    pub fn report_spoofed_broker_event(
        &self,
        topic: &str,
        source_client_id: &str,
        reason: &str,
    ) -> OcsfEvent {
        let now = Utc::now().timestamp_millis();
        let metadata = OcsfMetadata::default();
        Self::build_detection(
            now,
            &metadata,
            "Spoofed Broker Event",
            &format!(
                "Non-broker client {} published on broker topic {} ({})",
                source_client_id, topic, reason
            ),
            if source_client_id.is_empty() {
                None
            } else {
                Some(source_client_id.to_string())
            },
        )
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

        // Guard against spoofed broker events under /mcafee/event/dxl/#
        if topic.starts_with("/mcafee/event/dxl/") {
            if !KNOWN_BROKER_EVENT_TOPICS.contains(&topic) {
                alerts.push(Self::build_detection(
                    now,
                    &metadata,
                    "Spoofed Broker Event",
                    &format!(
                        "Client {} published to unrecognized broker event topic {}",
                        source_client_id, topic
                    ),
                    if source_client_id.is_empty() {
                        None
                    } else {
                        Some(source_client_id.to_string())
                    },
                ));
                return alerts;
            }
            if topic == TOPIC_BROKER_STATE {
                let claimed_guid = payload.get("guid").and_then(|v| v.as_str());
                let guid_mismatch = !source_client_id.is_empty()
                    && claimed_guid.is_some_and(|g| g != source_client_id);
                if is_hex_thumbprint(source_client_id)
                    || claimed_guid.is_some_and(is_hex_thumbprint)
                    || guid_mismatch
                {
                    alerts.push(Self::build_detection(
                        now,
                        &metadata,
                        "Spoofed Broker Event",
                        &format!(
                            "Non-broker client {} attempted to spoof brokerstate event",
                            source_client_id
                        ),
                        if source_client_id.is_empty() {
                            None
                        } else {
                            Some(source_client_id.to_string())
                        },
                    ));
                    return alerts;
                }
            } else if !self.brokers.is_empty()
                && !source_client_id.is_empty()
                && !self.brokers.contains_key(source_client_id)
            {
                alerts.push(Self::build_detection(
                    now,
                    &metadata,
                    "Spoofed Broker Event",
                    &format!(
                        "Non-broker client {} attempted to publish broker event on {}",
                        source_client_id, topic
                    ),
                    Some(source_client_id.to_string()),
                ));
                return alerts;
            }
        }

        // (b) Unknown Thumbprint
        if !self.allowed_thumbprints.is_empty() {
            // Check Connect events
            if topic == TOPIC_CLIENT_CONNECT
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

            if topic == TOPIC_SVC_REGISTER
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
        if topic == TOPIC_CLIENT_CONNECT
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

        // Track for TTL (a) & Service Hijacking protection
        if topic == TOPIC_SVC_REGISTER {
            if let (Some(guid), Some(svc_type), Some(ttl), Some(reg_time)) = (
                payload.get("serviceGuid").and_then(|v| v.as_str()),
                payload.get("serviceType").and_then(|v| v.as_str()),
                payload.get("ttlMins").and_then(|v| v.as_u64()),
                payload.get("registrationTime").and_then(|v| v.as_i64()),
            ) {
                let new_owner = payload
                    .get("clientGuid")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());
                if let (Some(existing), Some(new_client)) =
                    (self.services.get(guid), new_owner.as_deref())
                    && let Some(old_client) = existing.client_guid.as_deref()
                    && normalize_identity(old_client) != normalize_identity(new_client)
                {
                    alerts.push(Self::build_detection(
                        now,
                        &metadata,
                        "Service Hijack Attempt",
                        &format!(
                            "Service {} ({}) registered by client {} was previously owned by {}",
                            guid, svc_type, new_client, old_client
                        ),
                        Some(new_client.to_string()),
                    ));
                }
                self.services.insert(
                    guid.to_string(),
                    ServiceState {
                        guid: guid.to_string(),
                        service_type: svc_type.to_string(),
                        client_guid: new_owner,
                        registration_time_secs: reg_time,
                        ttl_mins: ttl as u32,
                        reported: false,
                    },
                );
            }
        } else if topic == TOPIC_SVC_UNREGISTER
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

        // Certificate Revocation List event monitoring
        if topic == TOPIC_REVOCATION_LIST
            && let Some(raw_list) = payload.as_str()
        {
            for line in raw_list.lines() {
                let cert = normalize_thumbprint(line);
                if !cert.is_empty() {
                    alerts.push(Self::build_detection(
                        now,
                        &metadata,
                        "Certificate Revoked",
                        &format!("Certificate thumbprint revoked on fabric: {}", cert),
                        Some(cert),
                    ));
                }
            }
        }

        // Payload vs Envelope Identity Mismatch (Framing protection on non-broker topics)
        if !topic.starts_with("/mcafee/event/dxl/")
            && !source_client_id.is_empty()
            && !self.brokers.contains_key(source_client_id)
        {
            let sender_norm = normalize_identity(source_client_id);
            for field in ["agentGuid", "clientGuid", "certThumbprint"] {
                if let Some(claimed) = payload.get(field).and_then(|v| v.as_str()) {
                    let claimed_norm = normalize_identity(claimed);
                    if !claimed_norm.is_empty()
                        && !sender_norm.is_empty()
                        && claimed_norm != sender_norm
                    {
                        alerts.push(Self::build_detection(
                            now,
                            &metadata,
                            "Payload Identity Spoofing",
                            &format!(
                                "Client {} published on {} claiming {}={}",
                                source_client_id, topic, field, claimed
                            ),
                            Some(source_client_id.to_string()),
                        ));
                    }
                }
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
        if topic == TOPIC_FABRIC_CHANGE {
            alerts.push(Self::build_detection(
                now,
                &metadata,
                "Fabric Change Detected",
                "A fabric topology change or broker state change was detected.",
                None,
            ));
        } else if topic == TOPIC_BROKER_STATE {
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
                    let client_guid = svc_info
                        .get("clientGuid")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string());
                    seen.insert(guid.to_string());
                    self.services.insert(
                        guid.to_string(),
                        ServiceState {
                            guid: guid.to_string(),
                            service_type: svc_type.to_string(),
                            client_guid,
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
                if !is_hex_thumbprint(guid) {
                    seen.insert(guid.to_string());
                    self.brokers.insert(guid.to_string(), broker_info.clone());
                }
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

    #[test]
    fn test_spoofed_broker_subtopic_does_not_frame_victim_and_flags_attacker() {
        let mut engine = DetectionEngine::new(&test_config());
        let spoof_payload = json!({
            "certThumbprint": "victim_thumbprint",
            "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA"
        });

        // 1. Sub-topic under /mcafee/event/dxl/ that is not a real broker event topic
        let alerts = engine.process_event(
            "/mcafee/event/dxl/spoof/connect",
            &spoof_payload,
            "allowed_hash",
        );
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Spoofed Broker Event");
            assert_eq!(df.suser.as_deref(), Some("allowed_hash"));
        } else {
            panic!("Expected DetectionFinding");
        }

        // 2. Non-broker topic ending with /connect must NOT be parsed as a broker connect event,
        // and because certThumbprint != sender ("allowed_hash"), it flags Payload Identity Spoofing
        // against "allowed_hash" instead of framing "victim_thumbprint".
        let alerts = engine.process_event("/custom/app/connect", &spoof_payload, "allowed_hash");
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Payload Identity Spoofing");
            assert_eq!(df.suser.as_deref(), Some("allowed_hash"));
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_non_broker_publishing_to_broker_topic_after_sync_is_flagged() {
        let mut engine = DetectionEngine::new(&test_config());
        engine.process_broker_sync_response(&json!({
            "brokers": {
                "{broker-1}": { "guid": "{broker-1}" }
            }
        }));

        let spoof_payload = json!({
            "certThumbprint": "victim_thumbprint",
            "cipher": "TLS_RSA_WITH_AES_128_CBC_SHA"
        });
        let alerts = engine.process_event(
            "/mcafee/event/dxl/clientregistry/connect",
            &spoof_payload,
            "allowed_hash",
        );
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Spoofed Broker Event");
            assert_eq!(df.suser.as_deref(), Some("allowed_hash"));
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_service_hijack_attempt_detected() {
        let mut engine = DetectionEngine::new(&test_config());
        let now_secs = Utc::now().timestamp();

        let legit_reg = json!({
            "serviceGuid": "{epo-service-guid}",
            "serviceType": "/mcafee/service/epo/remote",
            "clientGuid": "allowed_hash",
            "ttlMins": 60,
            "registrationTime": now_secs
        });
        let alerts = engine.process_event(
            "/mcafee/event/dxl/svcregistry/register",
            &legit_reg,
            "{broker-1}",
        );
        assert!(alerts.is_empty());

        // Another client registers the exact same serviceGuid
        let hijack_reg = json!({
            "serviceGuid": "{epo-service-guid}",
            "serviceType": "/mcafee/service/epo/remote",
            "clientGuid": "attacker_client_guid",
            "ttlMins": 60,
            "registrationTime": now_secs + 5
        });
        let alerts = engine.process_event(
            "/mcafee/event/dxl/svcregistry/register",
            &hijack_reg,
            "{broker-1}",
        );
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Service Hijack Attempt");
            assert_eq!(df.suser.as_deref(), Some("attacker_client_guid"));
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_certificate_revocation_list_event_detected() {
        let mut engine = DetectionEngine::new(&test_config());
        let payload = json!("84841B6FD81483746DC7390E8E44DFA4C86E1BA8\n");
        let alerts =
            engine.process_event("/mcafee/event/dxl/revocation/list", &payload, "{broker-1}");
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Certificate Revoked");
            assert_eq!(
                df.suser.as_deref(),
                Some("84841b6fd81483746dc7390e8e44dfa4c86e1ba8")
            );
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_payload_identity_spoofing_on_tie_detection_topic() {
        let mut engine = DetectionEngine::new(&test_config());
        let fake_tie_detection = json!({
            "agentGuid": "{68125cd6-a5d8-11e6-348e-000c29663178}",
            "detectionTime": 1481301038,
            "localReputation": 1,
            "name": "RANSOMWARE.EXE",
            "remediationAction": 5
        });

        let alerts = engine.process_event(
            "/mcafee/event/tie/file/detection",
            &fake_tie_detection,
            "allowed_hash",
        );
        assert_eq!(alerts.len(), 1);
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Payload Identity Spoofing");
            assert_eq!(df.suser.as_deref(), Some("allowed_hash"));
            assert!(
                df.finding_info
                    .desc
                    .contains("{68125cd6-a5d8-11e6-348e-000c29663178}")
            );
        } else {
            panic!("Expected DetectionFinding");
        }
    }

    #[test]
    fn test_brokerstate_spoofing_rejected_without_poisoning_brokers_map() {
        let mut engine = DetectionEngine::new(&test_config());
        let attacker_thumb = "5a752ed6a24f6d2dd77634b0c68dd729b48d4613";
        let spoof_state = json!({
            "guid": attacker_thumb,
            "bridges": [],
            "startTime": 1700000000
        });
        let alerts = engine.process_event(
            "/mcafee/event/dxl/brokerregistry/brokerstate",
            &spoof_state,
            attacker_thumb,
        );
        assert_eq!(alerts.len(), 1);
        assert!(!engine.brokers.contains_key(attacker_thumb));
        if let OcsfEvent::DetectionFinding(df) = &alerts[0] {
            assert_eq!(df.finding_info.title, "Spoofed Broker Event");
            assert_eq!(df.suser.as_deref(), Some(attacker_thumb));
        } else {
            panic!("Expected DetectionFinding");
        }
    }
}
