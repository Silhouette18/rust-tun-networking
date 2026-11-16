use byteorder::{BigEndian, ByteOrder};
use std::net::UdpSocket;
use std::time::Duration;
use std::sync::{Arc};
use std::time::Instant;
use crate::ipv4::calculate_sum;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct UdpConnectionKey {
    pub src_ip: [u8; 4],
    pub src_port: u16,
}

#[derive(Debug)]
pub struct UdpConnection {
    pub socket: Arc<UdpSocket>,
    pub last_active: Instant, 
}

#[derive(Debug)]
pub struct Udp {
    pub src_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub check_sum: u16,
}

impl Udp {
    pub fn new(buf: &[u8]) -> Self {
	Self {
	    src_port: BigEndian::read_u16(&buf[0..2]),
	    dest_port: BigEndian::read_u16(&buf[2..4]),
	    length: BigEndian::read_u16(&buf[4..6]),
	    check_sum: BigEndian::read_u16(&buf[6..8]),
    }
  }
   pub fn make_reply(buf: &[u8]) -> Vec<u8> {
	let mut outgoing = buf.to_vec();

	for i in 0..2 {
	    outgoing.swap(0 + i, 2 + i);
    }

	outgoing[6] = 0;
	outgoing[7] = 0;

	outgoing
  }

  pub fn extract_domain_name(buf: &[u8]) -> String {
	let mut index = 20;
	let mut domain_name= String::new();

	while index < buf.len() {
	    let label_len = buf[index] as usize;

	    if label_len == 0 { break }

	    if !domain_name.is_empty() {
		domain_name.push('.');
	    }

	   let start = index + 1;
	   let end = start + label_len;

	   if end > buf.len() { break }
	
	   let label = String::from_utf8_lossy(&buf[start..end]);
	   domain_name.push_str(&label);

	   index += 1 + label_len;
    }
	domain_name
  }

  pub fn handle_dns(buf: &[u8]) -> Vec<u8> {
	let requested_domain = Udp::extract_domain_name(buf);
	println!("Someone is asking for: {}", requested_domain);

	let mut	outgoing = buf.to_vec();

	outgoing[10] |= 0x80;
	outgoing[15] = 1;

	let answer_record: Vec<u8> = vec![
                0xc0, 0x0c,             // Pointer to domain name
                0x00, 0x01,             // Type A
                0x00, 0x01,             // Class IN
                0x00, 0x00, 0x01, 0x2c, // TTL 300
                0x00, 0x04,             // Data length (4 bytes)
                10, 0, 0, 2             // IP: 10.0.0.2
            ];

        outgoing.extend(answer_record);	

	let len = outgoing.len() as u16;

	BigEndian::write_u16(&mut outgoing[4..6], len);

	outgoing
  }
  pub fn cloudfire_dns_handle(buf: &[u8]) -> Vec<u8> {
	let udp_part = &buf[..8];
	let dns_part = &buf[8..];

	let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
	socket.send_to(&dns_part, "1.1.1.1:53").unwrap();

	socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

	let mut response = [0; 4096];
	
	if let Ok((amount, _src_addr)) = socket.recv_from(&mut response) { 

	let mut outgoing: Vec<u8> = Vec::new();

	outgoing.extend_from_slice(&udp_part);
	outgoing.extend_from_slice(&response[..amount]);

	let len = outgoing.len() as u16;
	BigEndian::write_u16(&mut outgoing[4..6], len);

	return outgoing;	
    }
	buf.to_vec()
  }
  pub fn make_reply_payload(payload: &[u8], conn_key: &UdpConnectionKey, remote_ip: [u8; 4], remote_port: u16) -> Vec<u8> {
	let udp_length = (8 + payload.len()) as u16;
	let ip_length = (20 + udp_length) as u16;

        let mut udp_header: Vec<u8> = [0u8; 8].to_vec();
	
	BigEndian::write_u16(&mut udp_header[0..2], remote_port);
	BigEndian::write_u16(&mut udp_header[2..4], conn_key.src_port);
	BigEndian::write_u16(&mut udp_header[4..6], udp_length);
	BigEndian::write_u16(&mut udp_header[6..8], 0);	

	let mut ip_header: Vec<u8> = [0u8; 20].to_vec();
	
	ip_header[12..16].copy_from_slice(&remote_ip);
	ip_header[16..20].copy_from_slice(&conn_key.src_ip);
	ip_header[9] =  17;
        BigEndian::write_u16(&mut ip_header[2..4], ip_length);

	ip_header[10] = 0x00;
	ip_header[11] = 0x00;

	ip_header[0] = 0x45;
	ip_header[8] = 64;

        let checksum = calculate_sum(&ip_header);
	BigEndian::write_u16(&mut ip_header[10..12], checksum);
	
	let mut outgoing: Vec<u8> = Vec::new();

	outgoing.extend(ip_header);
	outgoing.extend(udp_header);
	outgoing.extend_from_slice(payload);
	
	outgoing	 
  }
}




