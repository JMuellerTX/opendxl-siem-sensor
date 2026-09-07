use crate::ocsf::OcsfEvent;
use std::collections::BTreeMap;

pub fn escape_cef_header(value: &str) -> String {
    value.replace('\\', "\\\\").replace('|', "\\|").replace('\n', "\\n").replace('\r', "\\r")
}

pub fn escape_cef_extension(value: &str) -> String {
    value.replace('\\', "\\\\").replace('=', "\\=").replace('\n', "\\n").replace('\r', "\\r")
}

pub fn format_cef(event: &OcsfEvent) -> String {
    let version = "0";
    let vendor = "OpenDXL";
    let product = "opendxl-siem-sensor";
    let dev_version = "1.0";
    let class_id = event.class_id().to_string();
    let name = event.event_name();
    let severity = event.severity_id().to_string();

    let mut header = format!(
        "CEF:{}|{}|{}|{}|{}|{}|{}|",
        version,
        escape_cef_header(vendor),
        escape_cef_header(product),
        escape_cef_header(dev_version),
        escape_cef_header(&class_id),
        escape_cef_header(name),
        escape_cef_header(&severity)
    );

    let mut ext = BTreeMap::new();
    match event {
        OcsfEvent::NetworkActivity(na) => {
            ext.insert("deviceCustomNumber1", na.type_uid.to_string());
            ext.insert("deviceCustomNumber1Label", "type_uid".to_string());
            ext.insert("deviceCustomString1", na.client_guid.clone());
            ext.insert("deviceCustomString1Label", "client_guid".to_string());

            if let Some(src) = &na.src_endpoint
                && let Some(ip) = &src.ip {
                    ext.insert("src", ip.clone());
            }
            if let Some(info) = &na.connection_info {
                ext.insert("app", info.protocol_name.clone());
            }
            if let Some(tls) = &na.tls {
                ext.insert("deviceCustomString2", tls.version.clone());
                ext.insert("deviceCustomString2Label", "tls_version".to_string());
                if let Some(cipher) = tls.cipher_suites.first() {
                    ext.insert("deviceCustomString3", cipher.clone());
                    ext.insert("deviceCustomString3Label", "cipher".to_string());
                }
                if let Some(cert) = &tls.certificate {
                    ext.insert("deviceCustomString4", cert.fingerprint.clone());
                    ext.insert("deviceCustomString4Label", "cert_thumbprint".to_string());
                }
            }
        }
        OcsfEvent::ApiActivity(aa) => {
            ext.insert("deviceCustomNumber1", aa.type_uid.to_string());
            ext.insert("deviceCustomNumber1Label", "type_uid".to_string());
            ext.insert("deviceCustomString1", aa.api.service.uid.clone());
            ext.insert("deviceCustomString1Label", "service_uid".to_string());
            ext.insert("deviceCustomString2", aa.api.service.name.clone());
            ext.insert("deviceCustomString2Label", "service_name".to_string());
            if let Some(actor) = &aa.actor {
                ext.insert("deviceCustomString3", actor.user.uid.clone());
                ext.insert("deviceCustomString3Label", "client_guid".to_string());
            }
        }
        OcsfEvent::DetectionFinding(df) => {
            ext.insert("deviceCustomNumber1", df.type_uid.to_string());
            ext.insert("deviceCustomNumber1Label", "type_uid".to_string());
            ext.insert("msg", df.finding_info.desc.clone());
            if let Some(suser) = &df.suser {
                ext.insert("suser", suser.clone());
            }
        }
    }

    let mut ext_str = String::new();
    for (k, v) in ext {
        ext_str.push_str(&format!("{}={} ", k, escape_cef_extension(&v)));
    }

    header.push_str(ext_str.trim_end());
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocsf::*;

    #[test]
    fn test_escape_cef() {
        assert_eq!(escape_cef_header("foo|bar\\baz"), "foo\\|bar\\\\baz");
        assert_eq!(escape_cef_extension("key=value\\line\n"), "key\\=value\\\\line\\n");
    }

    #[test]
    fn test_format_cef_network() {
        let ev = NetworkActivity {
            activity_id: 1,
            activity_name: "Connect".to_string(),
            category_uid: 4,
            category_name: "Network Activity".to_string(),
            class_uid: 4001,
            class_name: "Network Activity".to_string(),
            severity_id: 1,
            severity: "Informational".to_string(),
            time: 1234567890,
            type_uid: 400101,
            type_name: "Network Connect".to_string(),
            metadata: OcsfMetadata::default(),
            src_endpoint: None,
            tls: None,
            connection_info: None,
            client_guid: "client-123".to_string(),
            client_instance_guid: None,
        };

        let cef = format_cef(&OcsfEvent::NetworkActivity(ev));
        assert_eq!(cef, "CEF:0|OpenDXL|opendxl-siem-sensor|1.0|4001|Connect|1|deviceCustomNumber1=400101 deviceCustomNumber1Label=type_uid deviceCustomString1=client-123 deviceCustomString1Label=client_guid");
    }

    #[test]
    fn test_format_cef_network_tls() {
        let ev = NetworkActivity {
            activity_id: 1,
            activity_name: "Connect".to_string(),
            category_uid: 4,
            category_name: "Network Activity".to_string(),
            class_uid: 4001,
            class_name: "Network Activity".to_string(),
            severity_id: 1,
            severity: "Informational".to_string(),
            time: 1234567890,
            type_uid: 400101,
            type_name: "Network Connect".to_string(),
            metadata: OcsfMetadata::default(),
            src_endpoint: Some(OcsfEndpoint {
                uid: None,
                ip: Some("172.17.0.1".to_string()),
            }),
            tls: Some(OcsfTls {
                version: "TLSv1.3".to_string(),
                cipher_suites: vec!["TLS_AES_256_GCM_SHA384".to_string()],
                certificate: Some(OcsfCertificate {
                    fingerprint: "5a752ed6a24f6d2dd77634b0c68dd729b48d4613".to_string(),
                }),
            }),
            connection_info: Some(OcsfConnectionInfo {
                protocol_name: "mqtt".to_string(),
            }),
            client_guid: "5a752ed6a24f6d2dd77634b0c68dd729b48d4613".to_string(),
            client_instance_guid: Some("c5c018fe-812e-47a3-856d-9f8a9dfb1426".to_string()),
        };

        let cef = format_cef(&OcsfEvent::NetworkActivity(ev));
        assert_eq!(cef, "CEF:0|OpenDXL|opendxl-siem-sensor|1.0|4001|Connect|1|app=mqtt deviceCustomNumber1=400101 deviceCustomNumber1Label=type_uid deviceCustomString1=5a752ed6a24f6d2dd77634b0c68dd729b48d4613 deviceCustomString1Label=client_guid deviceCustomString2=TLSv1.3 deviceCustomString2Label=tls_version deviceCustomString3=TLS_AES_256_GCM_SHA384 deviceCustomString3Label=cipher deviceCustomString4=5a752ed6a24f6d2dd77634b0c68dd729b48d4613 deviceCustomString4Label=cert_thumbprint src=172.17.0.1");
    }
}
