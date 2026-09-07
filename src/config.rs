use ini::Ini;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct DxlConfig {
    pub broker_cert_chain: String,
    pub cert_file: String,
    pub private_key: String,
    pub client_id: String,
    pub tls_min_version: String,
    pub verify_hostname: bool,
    pub tls_ciphers: Option<String>,
    pub brokers: Vec<Broker>,
    pub syslog_host: Option<String>,
    pub syslog_port: Option<u16>,
    pub syslog_protocol: Option<String>,
    pub service_ttl_grace_period_mins: u32,
    pub allowed_thumbprints: Vec<String>,
    pub sensitive_topics: Vec<String>,
    pub webhook_url: Option<String>,
    pub kafka_brokers: Option<String>,
    pub kafka_topic: Option<String>,
}

impl Default for DxlConfig {
    fn default() -> Self {
        Self {
            broker_cert_chain: "".to_string(),
            cert_file: "".to_string(),
            private_key: "".to_string(),
            client_id: "".to_string(),
            tls_min_version: "1.2".to_string(),
            verify_hostname: false,
            tls_ciphers: None,
            brokers: Vec::new(),
            syslog_host: None,
            syslog_port: None,
            syslog_protocol: None,
            service_ttl_grace_period_mins: 5,
            allowed_thumbprints: Vec::new(),
            sensitive_topics: Vec::new(),
            webhook_url: None,
            kafka_brokers: None,
            kafka_topic: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Broker {
    pub id: String,
    pub port: u16,
    pub host: String,
    pub ip: String,
}

impl DxlConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let conf = Ini::load_from_file(&path)?;

        let base_dir = path.as_ref().parent().unwrap_or(Path::new(""));
        let resolve_path = |p: &str| -> String {
            let p_path = Path::new(p);
            if p_path.is_absolute() {
                p.to_string()
            } else {
                base_dir.join(p).to_string_lossy().to_string()
            }
        };

        let certs = conf.section(Some("Certs")).ok_or("Missing [Certs] section")?;
        let broker_cert_chain = resolve_path(certs.get("BrokerCertChain").ok_or("Missing BrokerCertChain")?);
        let cert_file = resolve_path(certs.get("CertFile").ok_or("Missing CertFile")?);
        let private_key = resolve_path(certs.get("PrivateKey").ok_or("Missing PrivateKey")?);

        let general = conf.section(Some("General")).ok_or("Missing [General] section")?;
        let client_id = general.get("ClientId").map(|s| s.to_string()).unwrap_or_else(|| {
            format!("{{{}}}", uuid::Uuid::new_v4().to_string().to_lowercase())
        });
        let tls_min_version = general.get("TlsMinVersion").unwrap_or("1.2").to_string();
        let verify_hostname = general.get("VerifyHostname")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false); // C-1 E: VerifyHostname=false by default
        let tls_ciphers = general.get("TlsCiphers").map(|s| s.to_string());

        let brokers_sec = conf.section(Some("Brokers")).ok_or("Missing [Brokers] section")?;
        let mut brokers = Vec::new();
        // The value is guid;port;host;ip
        for (_, v) in brokers_sec.iter() {
            let parts: Vec<&str> = v.split(';').collect();
            if parts.len() >= 4 {
                brokers.push(Broker {
                    id: parts[0].to_string(),
                    port: parts[1].parse().unwrap_or(8883),
                    host: parts[2].to_string(),
                    ip: parts[3].to_string(),
                });
            }
        }

        let syslog = conf.section(Some("Syslog"));
        let syslog_host = syslog.and_then(|s| s.get("Host")).map(|s| s.to_string());
        let syslog_port = syslog.and_then(|s| s.get("Port")).and_then(|p| p.parse().ok());
        let syslog_protocol = syslog.and_then(|s| s.get("Protocol")).map(|s| s.to_string());

        let detections = conf.section(Some("Detections"));
        let service_ttl_grace_period_mins = detections
            .and_then(|d| d.get("ServiceTtlGracePeriodMins"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
            
        let allowed_thumbprints = detections
            .and_then(|d| d.get("AllowedThumbprints"))
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();
            
        let sensitive_topics = detections
            .and_then(|d| d.get("SensitiveTopics"))
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let webhook = conf.section(Some("Webhook"));
        let webhook_url = webhook.and_then(|w| w.get("Url")).map(|s| s.to_string());

        let kafka = conf.section(Some("Kafka"));
        let kafka_brokers = kafka.and_then(|k| k.get("Brokers")).map(|s| s.to_string());
        let kafka_topic = kafka.and_then(|k| k.get("Topic")).map(|s| s.to_string());

        Ok(Self {
            broker_cert_chain,
            cert_file,
            private_key,
            client_id,
            tls_min_version,
            verify_hostname,
            tls_ciphers,
            brokers,
            syslog_host,
            syslog_port,
            syslog_protocol,
            service_ttl_grace_period_mins,
            allowed_thumbprints,
            sensitive_topics,
            webhook_url,
            kafka_brokers,
            kafka_topic,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[Certs]").unwrap();
        writeln!(file, "BrokerCertChain=ca-bundle.crt").unwrap();
        writeln!(file, "CertFile=client.crt").unwrap();
        writeln!(file, "PrivateKey=client.key").unwrap();
        writeln!(file, "[General]").unwrap();
        writeln!(file, "ClientId={{1234}}").unwrap();
        writeln!(file, "[Brokers]").unwrap();
        writeln!(file, "mybroker=id1;8883;broker.local;127.0.0.1").unwrap();
        writeln!(file, "ipv6broker=id2;8883;broker.ipv6;[::1]").unwrap();

        let config = DxlConfig::load(file.path()).unwrap();
        assert_eq!(config.client_id, "{1234}");
        assert_eq!(config.brokers.len(), 2);
        assert_eq!(config.brokers[1].ip, "[::1]");
        assert_eq!(config.brokers[0].port, 8883);
    }
}
