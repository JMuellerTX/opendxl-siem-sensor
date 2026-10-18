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

fn section_ci<'a>(conf: &'a Ini, name: &str) -> Option<&'a ini::Properties> {
    conf.section(Some(name)).or_else(|| {
        conf.iter()
            .find(|(sec, _)| sec.is_some_and(|s| s.eq_ignore_ascii_case(name)))
            .map(|(_, props)| props)
    })
}

fn get_ci<'a>(props: &'a ini::Properties, key: &str) -> Option<&'a str> {
    props.get(key).or_else(|| {
        props
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    })
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

fn parse_broker_line(value: &str) -> Option<Broker> {
    let parts: Vec<&str> = value.split(';').map(|s| s.trim()).collect();
    match parts.len() {
        2 => {
            // port;host
            let port = parts[0].parse().ok()?;
            let host = parts[1].to_string();
            if host.is_empty() {
                return None;
            }
            Some(Broker {
                id: String::new(),
                port,
                ip: host.clone(),
                host,
            })
        }
        3 => {
            // Either port;host;ip (no id) or id;port;host (no ip)
            if let Ok(port) = parts[0].parse::<u16>() {
                let host = parts[1].to_string();
                let ip = if parts[2].is_empty() {
                    host.clone()
                } else {
                    parts[2].to_string()
                };
                Some(Broker {
                    id: String::new(),
                    port,
                    host,
                    ip,
                })
            } else {
                let port = parts[1].parse().ok()?;
                let host = parts[2].to_string();
                if host.is_empty() {
                    return None;
                }
                Some(Broker {
                    id: parts[0].to_string(),
                    port,
                    ip: host.clone(),
                    host,
                })
            }
        }
        n if n >= 4 => {
            // id;port;host;ip (where ip may be empty, falling back to host)
            let port = parts[1].parse().unwrap_or(8883);
            let host = parts[2].to_string();
            let ip = if parts[3].is_empty() {
                host.clone()
            } else {
                parts[3].to_string()
            };
            if host.is_empty() && ip.is_empty() {
                return None;
            }
            Some(Broker {
                id: parts[0].to_string(),
                port,
                host,
                ip,
            })
        }
        _ => None,
    }
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

        let certs = section_ci(&conf, "Certs").ok_or("Missing [Certs] section")?;
        let broker_cert_chain =
            resolve_path(get_ci(certs, "BrokerCertChain").ok_or("Missing BrokerCertChain")?);
        let cert_file = resolve_path(get_ci(certs, "CertFile").ok_or("Missing CertFile")?);
        let private_key = resolve_path(get_ci(certs, "PrivateKey").ok_or("Missing PrivateKey")?);

        let general = section_ci(&conf, "General").ok_or("Missing [General] section")?;
        let client_id = get_ci(general, "ClientId")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("{{{}}}", uuid::Uuid::new_v4().to_string().to_lowercase()));
        let tls_min_version = get_ci(general, "TlsMinVersion")
            .unwrap_or("1.2")
            .trim()
            .to_string();
        let verify_hostname = get_ci(general, "VerifyHostname")
            .map(parse_bool)
            .unwrap_or(false); // Off by default: broker certificates on real fabrics carry no matching SAN
        let tls_ciphers = get_ci(general, "TlsCiphers").map(|s| s.to_string());

        let brokers_sec = section_ci(&conf, "Brokers").ok_or("Missing [Brokers] section")?;
        let mut brokers = Vec::new();
        for (_, v) in brokers_sec.iter() {
            if let Some(broker) = parse_broker_line(v) {
                brokers.push(broker);
            }
        }

        let syslog = section_ci(&conf, "Syslog");
        let syslog_host = syslog
            .and_then(|s| get_ci(s, "Host"))
            .map(|s| s.trim().to_string());
        let syslog_port = syslog
            .and_then(|s| get_ci(s, "Port"))
            .and_then(|p| p.trim().parse().ok());
        let syslog_protocol = syslog
            .and_then(|s| get_ci(s, "Protocol"))
            .map(|s| s.trim().to_string());

        let detections = section_ci(&conf, "Detections");
        let service_ttl_grace_period_mins = detections
            .and_then(|d| get_ci(d, "ServiceTtlGracePeriodMins"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(5);

        let allowed_thumbprints = detections
            .and_then(|d| get_ci(d, "AllowedThumbprints"))
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let sensitive_topics = detections
            .and_then(|d| get_ci(d, "SensitiveTopics"))
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let webhook = section_ci(&conf, "Webhook");
        let webhook_url = webhook
            .and_then(|w| get_ci(w, "Url"))
            .map(|s| s.trim().to_string());

        let kafka = section_ci(&conf, "Kafka");
        let kafka_brokers = kafka
            .and_then(|k| get_ci(k, "Brokers"))
            .map(|s| s.trim().to_string());
        let kafka_topic = kafka
            .and_then(|k| get_ci(k, "Topic"))
            .map(|s| s.trim().to_string());

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
    #[test]
    fn test_load_readme_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[Certs]").unwrap();
        writeln!(file, "BrokerCertChain=ca-bundle.crt").unwrap();
        writeln!(file, "CertFile=client.crt").unwrap();
        writeln!(file, "PrivateKey=client.key").unwrap();
        writeln!(file, "[General]").unwrap();
        writeln!(file, "ClientId={{your-uuid-here}}").unwrap();
        writeln!(file, "VerifyHostname=false").unwrap();
        writeln!(file, "TlsMinVersion=1.2").unwrap();
        writeln!(file, "[Brokers]").unwrap();
        writeln!(file, "mybroker=mybroker;8883;broker.local;192.168.1.10").unwrap();
        writeln!(file, "[Detections]").unwrap();
        writeln!(
            file,
            "AllowedThumbprints=5a752ed6a24f6d2dd77634b0c68dd729b48d4613, a1b2c3d4"
        )
        .unwrap();
        writeln!(
            file,
            "SensitiveTopics=/mcafee/service/tie/file/reputation/set"
        )
        .unwrap();
        writeln!(file, "ServiceTtlGracePeriodMins=5").unwrap();
        writeln!(file, "[Syslog]").unwrap();
        writeln!(file, "Host=127.0.0.1").unwrap();
        writeln!(file, "Port=514").unwrap();
        writeln!(file, "Protocol=udp").unwrap();
        writeln!(file, "[Webhook]").unwrap();
        writeln!(file, "Url=http://siem.local:8080/ingest").unwrap();
        writeln!(file, "[Kafka]").unwrap();
        writeln!(file, "Brokers=kafka.local:9092").unwrap();
        writeln!(file, "Topic=dxl-events").unwrap();

        let config = DxlConfig::load(file.path()).unwrap();
        assert_eq!(config.allowed_thumbprints.len(), 2);
        assert_eq!(
            config.allowed_thumbprints[0],
            "5a752ed6a24f6d2dd77634b0c68dd729b48d4613"
        );
        assert_eq!(config.service_ttl_grace_period_mins, 5);
        assert_eq!(config.syslog_host.unwrap(), "127.0.0.1");
        assert_eq!(config.webhook_url.unwrap(), "http://siem.local:8080/ingest");
        assert_eq!(
            config.kafka_topic.unwrap(),
            "http://siem.local:8080/ingest"
                .split('/')
                .next()
                .map(|_| "dxl-events")
                .unwrap()
        );
    }

    #[test]
    fn test_load_python_lowercase_and_short_broker_formats() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[Certs]").unwrap();
        writeln!(file, "brokercertchain = ca-bundle.crt").unwrap();
        writeln!(file, "certfile = client.crt").unwrap();
        writeln!(file, "privatekey = client.key").unwrap();
        writeln!(file, "[General]").unwrap();
        writeln!(file, "clientid = {{abcd}}").unwrap();
        writeln!(file, "verifyhostname = yes").unwrap();
        writeln!(file, "tlsminversion = TLSv1.3").unwrap();
        writeln!(file, "[Brokers]").unwrap();
        writeln!(file, "three_field = id1 ; 8883 ; broker1.local").unwrap();
        writeln!(file, "two_field = 18883;broker2.local").unwrap();
        writeln!(file, "empty_ip = id3;28883;broker3.local;").unwrap();

        let config = DxlConfig::load(file.path()).unwrap();
        assert_eq!(config.client_id, "{abcd}");
        assert!(config.verify_hostname);
        assert_eq!(config.tls_min_version, "TLSv1.3");
        assert_eq!(config.brokers.len(), 3);
        assert_eq!(
            config.brokers[0],
            Broker {
                id: "id1".to_string(),
                port: 8883,
                host: "broker1.local".to_string(),
                ip: "broker1.local".to_string(),
            }
        );
        assert_eq!(
            config.brokers[1],
            Broker {
                id: "".to_string(),
                port: 18883,
                host: "broker2.local".to_string(),
                ip: "broker2.local".to_string(),
            }
        );
        assert_eq!(
            config.brokers[2],
            Broker {
                id: "id3".to_string(),
                port: 28883,
                host: "broker3.local".to_string(),
                ip: "broker3.local".to_string(),
            }
        );
    }
}
