use crate::config::DxlConfig;
use log::{error, info};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::io::AsyncWriteExt;

pub async fn start_syslog_sender(config: &DxlConfig) -> Option<mpsc::Sender<String>> {
    let host = config.syslog_host.clone()?;
    let port = config.syslog_port.unwrap_or(514);
    let protocol = config.syslog_protocol.clone().unwrap_or_else(|| "udp".to_string()).to_lowercase();
    
    let (tx, mut rx) = mpsc::channel::<String>(1000);
    let addr = format!("{}:{}", host, port);
    
    info!("Starting Syslog sender to {} via {}", addr, protocol);

    tokio::spawn(async move {
        if protocol == "udp" {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to bind UDP socket for syslog: {}", e);
                    return;
                }
            };
            
            while let Some(msg) = rx.recv().await {
                // RFC-5424 PRI = 134 (local0, info)
                let formatted = format!("<134>1 {} {} {} - - - {}\n", chrono::Utc::now().to_rfc3339(), "rust-sensor", "OpenDXL", msg);
                if let Err(e) = socket.send_to(formatted.as_bytes(), &addr).await {
                    error!("Failed to send syslog over UDP: {}", e);
                }
            }
        } else if protocol == "tcp" {
            let mut stream_opt = None;
            
            while let Some(msg) = rx.recv().await {
                let formatted = format!("<134>1 {} {} {} - - - {}\n", chrono::Utc::now().to_rfc3339(), "rust-sensor", "OpenDXL", msg);
                
                let mut retry = true;
                while retry {
                    if stream_opt.is_none() {
                        match TcpStream::connect(&addr).await {
                            Ok(stream) => { stream_opt = Some(stream); },
                            Err(e) => {
                                error!("Failed to connect to syslog server {}: {}", addr, e);
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                break; // Break retry loop and drop message (or keep it in a buffer)
                            }
                        }
                    }
                    
                    if let Some(stream) = &mut stream_opt {
                        if let Err(e) = stream.write_all(formatted.as_bytes()).await {
                            error!("Failed to send syslog over TCP: {}", e);
                            stream_opt = None;
                            // Retry connecting in next iteration
                        } else {
                            retry = false;
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
