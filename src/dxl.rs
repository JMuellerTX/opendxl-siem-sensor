use rmp::decode;
use rmp::encode;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

#[derive(Debug, PartialEq, Clone)]
pub struct DxlMessage {
    pub version: u8,
    pub message_type: u8,
    pub message_id: String,
    pub source_client_id: String,
    pub source_broker_id: String,
    pub broker_ids: Vec<String>,
    pub client_ids: Vec<String>,
    pub payload: Vec<u8>,
    
    // Request (0)
    pub reply_to_topic: Option<String>,
    pub service_id: Option<String>,
    
    // Response (1) / Error (3)
    pub request_message_id: Option<String>,
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    
    // version >= 1
    pub other_fields: HashMap<String, String>,
    
    // version >= 2
    pub source_tenant_guid: Option<String>,
    pub destination_tenant_guids: Vec<String>,
    
    // version >= 3
    pub source_client_instance_id: Option<String>,
}

pub const MESSAGE_TYPE_REQUEST: u8 = 0;
pub const MESSAGE_TYPE_RESPONSE: u8 = 1;
pub const MESSAGE_TYPE_EVENT: u8 = 2;
pub const MESSAGE_TYPE_ERROR: u8 = 3;

fn read_u8<R: Read>(rd: &mut R) -> Result<u8, std::io::Error> {
    let mut buf = [0; 1];
    rd.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16<R: Read>(rd: &mut R) -> Result<u16, std::io::Error> {
    let mut buf = [0; 2];
    rd.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32<R: Read>(rd: &mut R) -> Result<u32, std::io::Error> {
    let mut buf = [0; 4];
    rd.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

fn read_str_or_bin<R: Read>(rd: &mut R) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let marker = decode::read_marker(rd).map_err(|e| format!("{:?}", e))?;
    let len = match marker {
        rmp::Marker::FixStr(len) => len as u32,
        rmp::Marker::Str8 => read_u8(rd)? as u32,
        rmp::Marker::Str16 => read_u16(rd)? as u32,
        rmp::Marker::Str32 => read_u32(rd)?,
        rmp::Marker::Bin8 => read_u8(rd)? as u32,
        rmp::Marker::Bin16 => read_u16(rd)? as u32,
        rmp::Marker::Bin32 => read_u32(rd)?,
        _ => return Err(format!("Expected string or bin marker, got {:?}", marker).into()),
    };
    let mut buf = vec![0; len as usize];
    rd.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_string<R: Read>(rd: &mut R) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = read_str_or_bin(rd)?;
    Ok(String::from_utf8(bytes)?)
}

fn read_string_array<R: Read>(rd: &mut R) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let len = decode::read_array_len(rd)?;
    let mut arr = Vec::with_capacity(len as usize);
    for _ in 0..len {
        arr.push(read_string(rd)?);
    }
    Ok(arr)
}

pub fn parse_dxl_message(raw: &[u8]) -> Result<DxlMessage, Box<dyn std::error::Error>> {
    let mut cursor = Cursor::new(raw);
    
    let version: u8 = decode::read_int(&mut cursor)?;
    let message_type: u8 = decode::read_int(&mut cursor)?;
    
    let message_id = read_string(&mut cursor)?;
    let source_client_id = read_string(&mut cursor)?;
    let source_broker_id = read_string(&mut cursor)?;
    let broker_ids = read_string_array(&mut cursor)?;
    let client_ids = read_string_array(&mut cursor)?;
    let payload = read_str_or_bin(&mut cursor)?;
    
    let mut reply_to_topic = None;
    let mut service_id = None;
    let mut request_message_id = None;
    let mut error_code = None;
    let mut error_message = None;
    
    if message_type == MESSAGE_TYPE_REQUEST {
        reply_to_topic = Some(read_string(&mut cursor)?);
        service_id = Some(read_string(&mut cursor)?);
    } else if message_type == MESSAGE_TYPE_RESPONSE {
        request_message_id = Some(read_string(&mut cursor)?);
        service_id = Some(read_string(&mut cursor)?);
    } else if message_type == MESSAGE_TYPE_ERROR {
        request_message_id = Some(read_string(&mut cursor)?);
        service_id = Some(read_string(&mut cursor)?);
        error_code = Some(decode::read_int(&mut cursor)?);
        error_message = Some(read_string(&mut cursor)?);
    }
    
    let mut other_fields = HashMap::new();
    if version >= 1 {
        let len = decode::read_array_len(&mut cursor)?;
        let mut key = None;
        for _ in 0..len {
            let val = read_string(&mut cursor)?;
            if let Some(k) = key.take() {
                other_fields.insert(k, val);
            } else {
                key = Some(val);
            }
        }
        if let Some(k) = key {
            log::warn!("other_fields array had an odd length, ignoring trailing key: {}", k);
        }
    }
    
    let mut source_tenant_guid = None;
    let mut destination_tenant_guids = Vec::new();
    if version >= 2 {
        source_tenant_guid = Some(read_string(&mut cursor)?);
        destination_tenant_guids = read_string_array(&mut cursor)?;
    }
    
    let mut source_client_instance_id = None;
    if version >= 3 {
        source_client_instance_id = Some(read_string(&mut cursor)?);
    }
    
    Ok(DxlMessage {
        version,
        message_type,
        message_id,
        source_client_id,
        source_broker_id,
        broker_ids,
        client_ids,
        payload,
        reply_to_topic,
        service_id,
        request_message_id,
        error_code,
        error_message,
        other_fields,
        source_tenant_guid,
        destination_tenant_guids,
        source_client_instance_id,
    })
}

fn write_string(buf: &mut Vec<u8>, s: &str) -> Result<(), std::io::Error> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len < 32 {
        buf.write_all(&[0xa0 | (len as u8)])?;
    } else if len < 65536 {
        buf.write_all(&[0xda])?;
        buf.write_all(&(len as u16).to_be_bytes())?;
    } else {
        buf.write_all(&[0xdb])?;
        buf.write_all(&(len as u32).to_be_bytes())?;
    }
    buf.write_all(bytes)?;
    Ok(())
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), std::io::Error> {
    let len = bytes.len();
    if len < 32 {
        buf.write_all(&[0xa0 | (len as u8)])?;
    } else if len < 65536 {
        buf.write_all(&[0xda])?;
        buf.write_all(&(len as u16).to_be_bytes())?;
    } else {
        buf.write_all(&[0xdb])?;
        buf.write_all(&(len as u32).to_be_bytes())?;
    }
    buf.write_all(bytes)?;
    Ok(())
}

pub fn encode_dxl_message(msg: &DxlMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    
    encode::write_uint(&mut buf, msg.version as u64)?;
    encode::write_uint(&mut buf, msg.message_type as u64)?;
    
    write_string(&mut buf, &msg.message_id)?;
    write_string(&mut buf, &msg.source_client_id)?;
    write_string(&mut buf, &msg.source_broker_id)?;
    
    encode::write_array_len(&mut buf, msg.broker_ids.len() as u32)?;
    for bid in &msg.broker_ids { write_string(&mut buf, bid)?; }
    
    encode::write_array_len(&mut buf, msg.client_ids.len() as u32)?;
    for cid in &msg.client_ids { write_string(&mut buf, cid)?; }
    
    // Always encode payload as str/raw (use_bin_type=False equivalent)
    write_bytes(&mut buf, &msg.payload)?;
    
    if msg.message_type == MESSAGE_TYPE_REQUEST {
        write_string(&mut buf, msg.reply_to_topic.as_deref().unwrap_or(""))?;
        write_string(&mut buf, msg.service_id.as_deref().unwrap_or(""))?;
    } else if msg.message_type == MESSAGE_TYPE_RESPONSE {
        write_string(&mut buf, msg.request_message_id.as_deref().unwrap_or(""))?;
        write_string(&mut buf, msg.service_id.as_deref().unwrap_or(""))?;
    } else if msg.message_type == MESSAGE_TYPE_ERROR {
        write_string(&mut buf, msg.request_message_id.as_deref().unwrap_or(""))?;
        write_string(&mut buf, msg.service_id.as_deref().unwrap_or(""))?;
        encode::write_sint(&mut buf, msg.error_code.unwrap_or(0) as i64)?;
        write_string(&mut buf, msg.error_message.as_deref().unwrap_or(""))?;
    }
    
    if msg.version >= 1 {
        // flatten other_fields map into array
        encode::write_array_len(&mut buf, (msg.other_fields.len() * 2) as u32)?;
        // other_fields needs to be sorted for deterministic output (for tests at least)
        let mut keys: Vec<_> = msg.other_fields.keys().collect();
        keys.sort();
        for k in keys {
            write_string(&mut buf, k)?;
            write_string(&mut buf, msg.other_fields.get(k).unwrap())?;
        }
    }
    
    if msg.version >= 2 {
        write_string(&mut buf, msg.source_tenant_guid.as_deref().unwrap_or(""))?;
        encode::write_array_len(&mut buf, msg.destination_tenant_guids.len() as u32)?;
        for t in &msg.destination_tenant_guids { write_string(&mut buf, t)?; }
    }
    
    if msg.version >= 3 {
        write_string(&mut buf, msg.source_client_instance_id.as_deref().unwrap_or(""))?;
    }
    
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_golden_vectors() {
        let file = File::open("c:/src/opendxl/_local_verify/work/opendxl-client-java/golden.txt").unwrap();
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line.unwrap();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let name = parts[0];
                let hex = parts[1];
                let raw_bytes = from_hex(hex);
                
                let parsed = parse_dxl_message(&raw_bytes).expect(&format!("Failed to parse {}", name));
                let encoded = encode_dxl_message(&parsed).expect(&format!("Failed to encode {}", name));
                
                assert_eq!(raw_bytes, encoded, "Roundtrip failed for vector {}", name);
            }
        }
    }
}
