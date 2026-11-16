use byteorder::{BigEndian, ByteOrder};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct IPv4 {
    pub version: u8,
    pub ihl: u8,
    pub length: u16,
    pub header_length: u8, 
    pub proto: u8, 
    pub src_ip: u32,
    pub dest_ip: u32,
}

impl IPv4 {
   pub fn new(buf: &[u8]) -> Self {

    let first_byte = buf[0];

    let ver = first_byte >> 4;
    let ih = first_byte & 0x0F;

    let header_l = ih * 4;

    Self {
	version: ver,
	ihl: ih,
	length: BigEndian::read_u16(&buf[2..4]),
	header_length: header_l,
	proto: buf[9],
	src_ip: BigEndian::read_u32(&buf[12..16]),
	dest_ip: BigEndian::read_u32(&buf[16..20]),
    }
  }

  pub fn make_reply(buf: &mut [u8]) -> () {
    for i in 0..4 {
	buf.swap(12 + i, 16 + i);
}
	buf[10] = 0;
	buf[11] = 0;

        let new_checksum = calculate_sum(buf);
    
        BigEndian::write_u16(&mut buf[10..12], new_checksum);
  }

  pub fn _pretty_ip(ipv4: &u32) -> Ipv4Addr  {
	let readeble_ip = Ipv4Addr::from(*ipv4);
	readeble_ip
    } 
}


pub fn calculate_sum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < buf.len() - 1 {
	let word = BigEndian::read_u16(&buf[i..i+2]);
	sum += word as u32;
	i += 2;
  }
    if i < buf.len() {
	let word = BigEndian::read_u16(&[buf[i], 0]);
	sum += word as u32;
  }  
    while (sum >> 16) > 0 {
	sum = (sum & 0xFFFF) + (sum >> 16);
  }
  
  !sum as u16
}

