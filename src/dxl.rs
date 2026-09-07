use rmp_serde::decode::from_slice;
use serde::Deserialize;

#[derive(Debug)]
pub struct DxlMessage {
    pub version: u8,
    pub message_type: u8,
    pub message_id: String,
    pub source_client_id: String,
    pub source_broker_id: String,
    pub broker_ids: Vec<String>,
    pub client_ids: Vec<String>,
    pub payload: Vec<u8>,
}

pub fn parse_dxl_message(raw: &[u8]) -> Result<DxlMessage, Box<dyn std::error::Error>> {
    let mut cursor = std::io::Cursor::new(raw);
    
    // In Python, DXL messages are packed as consecutive msgpack objects.
    let version: u8 = rmp_serde::decode::from_read(&mut cursor)?;
    let message_type: u8 = rmp_serde::decode::from_read(&mut cursor)?;
    
    let message_id: String = rmp_serde::decode::from_read(&mut cursor)?;
    let source_client_id: String = rmp_serde::decode::from_read(&mut cursor)?;
    let source_broker_id: String = rmp_serde::decode::from_read(&mut cursor)?;
    let broker_ids: Vec<String> = rmp_serde::decode::from_read(&mut cursor)?;
    let client_ids: Vec<String> = rmp_serde::decode::from_read(&mut cursor)?;
    
    // payload can be bytes
    let payload: Vec<u8> = rmp_serde::decode::from_read(&mut cursor)?;
    
    Ok(DxlMessage {
        version,
        message_type,
        message_id,
        source_client_id,
        source_broker_id,
        broker_ids,
        client_ids,
        payload,
    })
}
