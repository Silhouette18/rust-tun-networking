use byteorder::{BigEndian, ByteOrder};
use crate::ipv4::calculate_sum;

#[derive(Debug)]
pub struct Icmp {
    pub types: u8,
    pub code: u8,
    pub check_sum: u16,
    pub indentifier: u16,
    pub counter: u16,
}

impl Icmp {
    pub fn new(buf: &[u8]) -> Self {
	Self {
	    types: buf[0],
	    code: buf[1],
	    check_sum: BigEndian::read_u16(&buf[2..4]),
	    indentifier: BigEndian::read_u16(&buf[4..6]),
	    counter: BigEndian::read_u16(&buf[6..8]),
    }
  }
    pub fn make_reply(buf: &[u8]) -> Vec<u8> {
	let mut outgoing = buf.to_vec();

	outgoing[0] = 0;

	outgoing[2] = 0;
	outgoing[3] = 0;
	
	let new_checksum = calculate_sum(&outgoing);

	BigEndian::write_u16(&mut outgoing[2..4], new_checksum);

	outgoing
  }
}
