use crate::config::DxlConfig;
use log::{error, info};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

pub async fn start_syslog_sender(config: &DxlConfig) -> Option<mpsc::Sender<String>> {
    let host = config.syslog_host.clone()?;
    let port = config.syslog_port.unwrap_or(514);
    let protocol = config
        .syslog_protocol
        .clone()
        .unwrap_or_else(|| "udp".to_string())
        .to_lowercase();

    let (tx, mut rx) = mpsc::channel::<String>(1000);
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    let is_ipv6 = clean_host.contains(':');
    let addr = if is_ipv6 {
        format!("[{}]:{}", clean_host, port)
    } else {
        format!("{}:{}", clean_host, port)
    };

    info!("Starting Syslog sender to {} via {}", addr, protocol);

    tokio::spawn(async move {
        if protocol == "udp" {
            let bind_addr = if is_ipv6 { "[::]:0" } else { "0.0.0.0:0" };
            let socket = match UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to bind UDP socket for syslog: {}", e);
                    return;
                }
            };

            while let Some(msg) = rx.recv().await {
                // RFC-5424 PRI = 134 (local0, info); no trailing LF on UDP datagrams (RFC 5426 §3.2)
                let formatted = format!(
                    "<134>1 {} {} {} - - - {}",
                    chrono::Utc::now().to_rfc3339(),
                    "opendxl-siem-sensor",
                    "OpenDXL",
                    msg
                );
                if let Err(e) = socket.send_to(formatted.as_bytes(), &addr).await {
                    error!("Failed to send syslog over UDP: {}", e);
                }
            }
        } else if protocol == "tcp" {
            let mut stream_opt = None;

            while let Some(msg) = rx.recv().await {
                let formatted = format!(
                    "<134>1 {} {} {} - - - {}\n",
                    chrono::Utc::now().to_rfc3339(),
                    "opendxl-siem-sensor",
                    "OpenDXL",
                    msg
                );

                let mut retry = true;
                while retry {
                    if stream_opt.is_none() {
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            TcpStream::connect(&addr),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                stream_opt = Some(stream);
                            }
                            Ok(Err(e)) => {
                                error!("Failed to connect to syslog server {}: {}", addr, e);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                break; // Break retry loop and drop message (or keep it in a buffer)
                            }
                            Err(_) => {
                                error!("Timed out connecting to syslog server {}", addr);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                break;
                            }
                        }
                    }

                    if let Some(stream) = &mut stream_opt {
                        match tokio::time::timeout(
                            Duration::from_secs(5),
                            stream.write_all(formatted.as_bytes()),
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                retry = false;
                            }
                            Ok(Err(e)) => {
                                error!("Failed to send syslog over TCP: {}", e);
                                stream_opt = None;
                                // Retry connecting in next iteration
                            }
                            Err(_) => {
                                error!("Timed out sending syslog over TCP to {}", addr);
                                stream_opt = None;
                            }
                        }
                    }
                }
            }
        } else {
            error!("Unsupported syslog protocol: {}", protocol);
        }
    });

    Some(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_syslog_sender_no_host() {
        let config = DxlConfig::default();
        let tx = start_syslog_sender(&config).await;
        assert!(tx.is_none());
    }

    #[tokio::test]
    async fn test_syslog_sender_with_host() {
        let config = DxlConfig {
            syslog_host: Some("127.0.0.1".to_string()),
            syslog_protocol: Some("udp".to_string()),
            ..Default::default()
        };
        let tx = start_syslog_sender(&config).await;
        assert!(tx.is_some());
    }
}
