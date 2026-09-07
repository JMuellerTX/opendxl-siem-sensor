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
    let product = "RustSensor";
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
            client_guid: "client-123".to_string(),
        };

        let cef = format_cef(&OcsfEvent::NetworkActivity(ev));
        assert_eq!(cef, "CEF:0|OpenDXL|RustSensor|1.0|4001|Connect|1|deviceCustomNumber1=400101 deviceCustomNumber1Label=type_uid deviceCustomString1=client-123 deviceCustomString1Label=client_guid");
    }
}
