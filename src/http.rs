use crate::config::DxlConfig;
use crate::ocsf::OcsfEvent;
use log::{error, info};
use reqwest::Client;
use tokio::sync::mpsc;

pub async fn start_http_sender(config: &DxlConfig) -> Option<mpsc::Sender<OcsfEvent>> {
    let url = config.webhook_url.clone()?;
    let (tx, mut rx) = mpsc::channel::<OcsfEvent>(1000);
    
    info!("Starting HTTP Webhook sender to {}", url);
    let client = Client::new();

    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match client.post(&url).json(&event).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        error!("Webhook failed with status: {}", resp.status());
                    }
                }
                Err(e) => {
                    error!("Failed to send to webhook: {}", e);
                }
            }
        }
    });

    Some(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_sender_no_url() {
        let config = DxlConfig::default();
        let tx = start_http_sender(&config).await;
        assert!(tx.is_none());
    }

    #[tokio::test]
    async fn test_http_sender_with_url() {
        let config = DxlConfig {
            webhook_url: Some("http://127.0.0.1:8080".to_string()),
            ..Default::default()
        };
        let tx = start_http_sender(&config).await;
        assert!(tx.is_some());
    }
}
