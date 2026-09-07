use serde::{Deserialize, Serialize};

// OCSF 1.x Common Fields

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfMetadata {
    pub product: OcsfProduct,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfProduct {
    pub name: String,
    pub vendor_name: String,
    pub version: String,
}

impl Default for OcsfMetadata {
    fn default() -> Self {
        Self {
            product: OcsfProduct {
                name: "OpenDXL Rust Sensor".to_string(),
                vendor_name: "OpenDXL".to_string(),
                version: "1.0.0".to_string(),
            },
        }
    }
}

// 4001 Network Activity (Connect / Disconnect)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkActivity {
    pub activity_id: i32, // 1: Connect, 2: Disconnect, etc.
    pub activity_name: String,
    pub category_uid: i32, // 4: Network Activity
    pub category_name: String,
    pub class_uid: i32, // 4001
    pub class_name: String,
    pub severity_id: i32, // 1: Informational
    pub severity: String,
    pub time: i64, // Epoch milliseconds
    pub type_uid: i32, // 400101 for connect
    pub type_name: String,
    pub metadata: OcsfMetadata,
    
    // Custom context
    pub src_endpoint: Option<OcsfEndpoint>,
    pub tls: Option<OcsfTls>,
    pub connection_info: Option<OcsfConnectionInfo>,
    pub client_guid: String, // Split out (thumbprint)
    pub client_instance_guid: Option<String>, // Full value
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfEndpoint {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfTls {
    pub version: String,
    pub cipher_suites: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<OcsfCertificate>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfCertificate {
    pub fingerprint: String, // thumbprint
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfConnectionInfo {
    pub protocol_name: String,
}

// 6003 API Activity (Register / Unregister)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiActivity {
    pub activity_id: i32, // 1: Read, 2: Create, 3: Update, 4: Delete
    pub activity_name: String,
    pub category_uid: i32, // 6: Application Activity
    pub category_name: String,
    pub class_uid: i32, // 6003
    pub class_name: String,
    pub severity_id: i32, // 1: Informational
    pub severity: String,
    pub time: i64, // Epoch milliseconds
    pub type_uid: i32, // 600302 for create (register), 600304 for delete (unregister)
    pub type_name: String,
    pub metadata: OcsfMetadata,
    
    pub api: OcsfApi,
    pub actor: Option<OcsfActor>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfApi {
    pub operation: String,
    pub service: OcsfService,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfService {
    pub name: String,
    pub uid: String, // Service GUID
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfActor {
    pub user: OcsfUser,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfUser {
    pub uid: String, // Client GUID
}

// 2004 Detection Finding
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DetectionFinding {
    pub activity_id: i32, // 1: Create
    pub activity_name: String,
    pub category_uid: i32, // 2: Findings
    pub category_name: String,
    pub class_uid: i32, // 2004
    pub class_name: String,
    pub severity_id: i32, // 3: Medium, 4: High, 5: Critical, 6: Fatal
    pub severity: String,
    pub time: i64, // Epoch milliseconds
    pub type_uid: i32, // 200401
    pub type_name: String,
    pub metadata: OcsfMetadata,
    
    pub finding_info: OcsfFindingInfo,
    pub suser: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OcsfFindingInfo {
    pub title: String,
    pub desc: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum OcsfEvent {
    NetworkActivity(NetworkActivity),
    ApiActivity(ApiActivity),
    DetectionFinding(DetectionFinding),
}

impl OcsfEvent {
    pub fn class_id(&self) -> i32 {
        match self {
            OcsfEvent::NetworkActivity(e) => e.class_uid,
            OcsfEvent::ApiActivity(e) => e.class_uid,
            OcsfEvent::DetectionFinding(e) => e.class_uid,
        }
    }
    
    pub fn event_name(&self) -> &str {
        match self {
            OcsfEvent::NetworkActivity(e) => &e.activity_name,
            OcsfEvent::ApiActivity(e) => &e.activity_name,
            OcsfEvent::DetectionFinding(e) => &e.finding_info.title,
        }
    }

    pub fn severity_id(&self) -> i32 {
        match self {
            OcsfEvent::NetworkActivity(e) => e.severity_id,
            OcsfEvent::ApiActivity(e) => e.severity_id,
            OcsfEvent::DetectionFinding(e) => e.severity_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_activity_serialization() {
        let na = NetworkActivity {
            activity_id: 1,
            activity_name: "Connect".to_string(),
            category_uid: 4,
            category_name: "Network Activity".to_string(),
            class_uid: 4001,
            class_name: "Network Activity".to_string(),
            severity_id: 1,
            severity: "Informational".to_string(),
            time: 1600000000000,
            type_uid: 400101,
            type_name: "Network Connect".to_string(),
            metadata: OcsfMetadata::default(),
            src_endpoint: None,
            tls: None,
            connection_info: None,
            client_guid: "test-guid".to_string(),
            client_instance_guid: None,
        };

        let event = OcsfEvent::NetworkActivity(na);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("Connect"));
        assert!(json.contains("test-guid"));
        assert_eq!(event.class_id(), 4001);
    }
}
