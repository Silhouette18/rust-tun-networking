use byteorder::{BigEndian, ByteOrder};
use crate::ipv4::calculate_sum;
use std::time::Instant;
use std::collections::VecDeque;

#[derive(Debug)]
pub struct UnackedPacket {
    pub expected_ack: u32,
    pub packed_bytes: Vec<u8>,
    pub sent_at: Instant,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct ConnectionKey {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dest_ip: [u8; 4],
    pub dest_port: u16,
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum TcpState {
    SynReceived,
    Established,
    FinWait,
    LastAck,
    Closed,
}

#[derive(Debug)]
pub struct Connection {
    pub state: TcpState,
    pub snd_next: u32,
    pub rcv_next: u32,
    pub last_active: Instant,
    pub unacked_queue: VecDeque<UnackedPacket>,
    pub upstream_tx: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    pub last_client_ts: u32,
    pub ts_clock: u32,
}

#[derive(Debug)]
pub struct Tcp {
    pub src_port: u16,
    pub dest_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub win_size: u16,
    pub header_len: u8,
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
}

impl Tcp {
    pub fn new(buf: &[u8]) -> Self {
      let offset_byte = buf[12];
      let flag_byte = buf[13];

      Self {
        src_port: BigEndian::read_u16(&buf[0..2]),
        dest_port: BigEndian::read_u16(&buf[2..4]),
        seq_num: BigEndian::read_u32(&buf[4..8]),
        ack_num: BigEndian::read_u32(&buf[8..12]),
        win_size: BigEndian::read_u16(&buf[14..16]),
        header_len: (offset_byte >> 4) * 4,
        
        fin: (flag_byte & 0x01) != 0,
        syn: (flag_byte & 0x02) != 0,
        rst: (flag_byte & 0x04) != 0,
        psh: (flag_byte & 0x08) != 0,
        ack: (flag_byte & 0x10) != 0,
    }
  }
   
   pub fn make_reply(buf: &[u8], src_ip: &[u8], dest_ip: &[u8], flags: u8, snd_next: u32, rcv_next: u32, ts_val: Option<u32>, ts_ecr: Option<u32>) -> Vec<u8> {
 
        let tcp_header_length = ((buf[12] >> 4) * 4) as usize;
        let mut outgoing_packet = Vec::new();
        outgoing_packet.extend_from_slice(&buf[..tcp_header_length]);

        for i in 0..2 {
            outgoing_packet.swap(0 + i, 2 + i);
        }

        BigEndian::write_u32(&mut outgoing_packet[4..8], snd_next);
        BigEndian::write_u32(&mut outgoing_packet[8..12], rcv_next);
        
        outgoing_packet[13] = flags;

	if let (Some(my_ts), Some(echo_ts)) = (ts_val, ts_ecr) {
            Self::update_tcp_timestamp_options(&mut outgoing_packet, tcp_header_length, my_ts, echo_ts);
        }

        outgoing_packet[16] = 0;
        outgoing_packet[17] = 0;

        let mut array: [u8; 12] = [0u8; 12];
        array[0..4].copy_from_slice(src_ip);
        array[4..8].copy_from_slice(dest_ip);
        array[9] = 6;
        BigEndian::write_u16(&mut array[10..12], outgoing_packet.len() as u16);

        let mut checksum_buffer = Vec::with_capacity(12 + outgoing_packet.len());
        checksum_buffer.extend_from_slice(&array);
        checksum_buffer.extend_from_slice(&outgoing_packet);
        
        let check_sum = calculate_sum(&checksum_buffer);
        BigEndian::write_u16(&mut outgoing_packet[16..18], check_sum);

        outgoing_packet
    }
 
   pub fn make_reply_payload(buf: &[u8], src_ip: &[u8], dest_ip: &[u8], flags: u8, snd_next: u32, rcv_next: u32, payload: &[u8], ts_val: Option<u32>, ts_ecr: Option<u32>) -> Vec<u8> {
	
    let tcp_header_length = ((buf[12] >> 4) * 4) as usize;

    let mut outgoing_packet = Vec::new();

    outgoing_packet.extend_from_slice(&buf[..tcp_header_length]);
    outgoing_packet.extend_from_slice(payload);

    for i in 0..2 {
        outgoing_packet.swap(0 + i, 2 + i);
    }

    BigEndian::write_u32(&mut outgoing_packet[4..8], snd_next);
    
    BigEndian::write_u32(&mut outgoing_packet[8..12], rcv_next);

    outgoing_packet[13] = flags;

    if let (Some(my_ts), Some(echo_ts)) = (ts_val, ts_ecr) {
        Self::update_tcp_timestamp_options(&mut outgoing_packet, tcp_header_length, my_ts, echo_ts);
    }

    outgoing_packet[16] = 0;
    outgoing_packet[17] = 0;

    let mut array: [u8; 12] = [0u8; 12];
    array[0..4].copy_from_slice(src_ip);
    array[4..8].copy_from_slice(dest_ip);
    array[9] = 6;
    BigEndian::write_u16(&mut array[10..12], outgoing_packet.len() as u16);

    let mut checksum_buffer = Vec::with_capacity(12 + outgoing_packet.len());
    checksum_buffer.extend_from_slice(&array);
    checksum_buffer.extend_from_slice(&outgoing_packet);
    
    let check_sum = calculate_sum(&checksum_buffer);

    BigEndian::write_u16(&mut outgoing_packet[16..18], check_sum);

    outgoing_packet
  }

  pub fn update_tcp_timestamp_options( tcp_bytes: &mut [u8],     header_len_bytes: usize,  my_ts_val: u32,  echo_ts_ecr: u32) {
   
    if header_len_bytes <= 20 || tcp_bytes.len() < header_len_bytes {
        return;
    }

    let mut i = 20; 
    while i < header_len_bytes {
        let kind = tcp_bytes[i];
        
        match kind {
            0 => break, 
            1 => i += 1, 
            8 => {
                if i + 10 <= header_len_bytes {
                    BigEndian::write_u32(&mut tcp_bytes[i + 2..i + 6], my_ts_val);
                    BigEndian::write_u32(&mut tcp_bytes[i + 6..i + 10], echo_ts_ecr);
                }
                break;
            }
            _ => {
                if i + 1 < header_len_bytes {
                    let len = tcp_bytes[i + 1] as usize;
                    if len == 0 { break; } 
                    i += len;
                } else {
                    break;
                }
            }
        }
    }
  }

pub fn extract_incoming_ts_val(tcp_bytes: &[u8], header_len_bytes: usize) -> Option<u32> {
    if header_len_bytes <= 20 || tcp_bytes.len() < header_len_bytes {
        return None;
    }

    let mut i = 20;
    while i < header_len_bytes {
        let kind = tcp_bytes[i];
        match kind {
            0 => break,
            1 => i += 1,
            8 => {
                if i + 10 <= header_len_bytes {
                    return Some(BigEndian::read_u32(&tcp_bytes[i + 2..i + 6]));
                }
                break;
            }
            _ => {
                if i + 1 < header_len_bytes {
                    let len = tcp_bytes[i + 1] as usize;
                    if len == 0 { break; }
                    i += len;
                } else {
                    break;
                }
            }
        }
    }
    None
  }
}
