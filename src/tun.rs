use tun_tap::{Iface, Mode};
use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use std::collections::HashMap;
use std::thread;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::net::{Ipv4Addr, UdpSocket, SocketAddr, TcpStream, IpAddr};
use std::io::{Read, Write};
use socket2::{Socket, Domain, Type, Protocol};
use std::process::Command;
use std::time::Instant;
use std::collections::VecDeque;
use std::time::Duration;
use crate::ipv4::IPv4;
use crate::icmp::Icmp;
use crate::udp::Udp;
use crate::udp::UdpConnection;
use crate::tcp::Tcp;
use crate::tcp::ConnectionKey;
use crate::tcp::Connection;
use crate::tcp::TcpState;
use crate::tcp::UnackedPacket;
use crate::udp::UdpConnectionKey;

pub fn create_tun() -> Result<(), std::io::Error> {
    let iface = Iface::without_packet_info("tun0", Mode::Tun)?;

    println!("Successfully created TUN device: {}", iface.name());

    Command::new("ip")
    .args(["addr", "add", "10.0.0.1/24", "dev", "tun0"])
    .output()
    .expect("Failed to assign IP to tun0");

    Command::new("ip")
    .args(["link", "set", "up", "dev", "tun0"])
    .output()
    .expect("Failed to bring tun0 up");

    let iface_arc = Arc::new(iface); 

    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    let iface_clone = Arc::clone(&iface_arc);

    thread::spawn(move || {
	    loop {
		let packet_bytes = rx.recv().unwrap();
		iface_clone.send(&packet_bytes).unwrap();
	    }
	});

    let mut buffer = BytesMut::zeroed(65536);

    let mut udp_hashmap: Arc<Mutex<HashMap<UdpConnectionKey, UdpConnection>>> = Arc::new(Mutex::new(HashMap::new()));
	
    let hashmap: Arc<Mutex<HashMap<ConnectionKey, Connection>>> = Arc::new(Mutex::new(HashMap::new()));

    let sweeper_map = Arc::clone(&hashmap);

    thread::spawn(move || {
	loop {
	    thread::sleep(std::time::Duration::from_secs(10));

	    let mut map = sweeper_map.lock().unwrap();
	    let now = Instant::now();

	    map.retain(|key, connection| {
		let is_active = now.duration_since(connection.last_active).as_secs() < 60;
		if !is_active {
		   println!("Sweeper: Dropping dead connection!");
		}
  	    is_active	
	  });
	}
	});

    let retransmit_map = Arc::clone(&hashmap);
    let retransmit_clone = tx.clone();


    thread::spawn(move || {

	loop {
	    thread::sleep(std::time::Duration::from_millis(100));

	    let mut map_guard = retransmit_map.lock().unwrap();
	
	    for (key, value) in map_guard.iter_mut() {
		if let Some(front_packet) = value.unacked_queue.front_mut() {

		if Instant::now().duration_since(front_packet.sent_at).as_millis() > 500 {
			let cloned = front_packet.packed_bytes.clone();
			retransmit_clone.send(cloned).unwrap();
			front_packet.sent_at = Instant::now();
			println!("Retransmitting lost packet!");
		}
	      }
	    }
	}	
});

    loop {

        let bytes_read = iface_arc.recv(&mut buffer).unwrap();
	
	let packet_data = buffer.split_to(bytes_read).freeze();

	if buffer.capacity() < 1504 {
	    buffer.resize(65536, 0);
	}

	let tx_clone = tx.clone();        

	if (packet_data[0] >> 4) != 4 {
 	   continue;
	}

        let parsed_packet = IPv4::new(&packet_data);

        let ip_header_length = (parsed_packet.ihl * 4) as usize;
        let total_length = parsed_packet.length as usize;


        if parsed_packet.proto == 1 {

            let icmp_bytes = &packet_data[ip_header_length..total_length];
            let icmp_packet = Icmp::new(icmp_bytes);

            if icmp_packet.types == 8 {
                println!("Intercepted Ping Request! Forging reply...");
                
		let new_icmp_segment = Icmp::make_reply(icmp_bytes);

		let mut final_packet = Vec::new();

		final_packet.extend_from_slice(&packet_data[0..ip_header_length]);
		final_packet.extend_from_slice(&new_icmp_segment);

		IPv4::make_reply(&mut final_packet[0..ip_header_length]);

		tx_clone.send(final_packet).unwrap();
                
                println!("Reply sent!");
            }
        }
	if parsed_packet.proto == 17 {
	    println!("Intercepted Udp Request! Forging reply..");	    
    
	    let mut map_guard = udp_hashmap.lock().unwrap();

	    let mut client_ip = [0u8; 4];
            client_ip.copy_from_slice(&packet_data[12..16]);

            let mut server_ip = [0u8; 4];
            server_ip.copy_from_slice(&packet_data[16..20]);
	    
	    let udp_bytes = &packet_data[ip_header_length..total_length];
	    let udp_packet = Udp::new(udp_bytes);

	    let payload_bytes = &packet_data[ip_header_length + 8..total_length];

	    let original_dest = Ipv4Addr::new(server_ip[0], server_ip[1], server_ip[2], server_ip[3]);

	    let target = if udp_packet.dest_port == 53 {
		let google_dns = Ipv4Addr::new(8,8,8,8);
		(google_dns, 53)
	    } else {
 		(original_dest, udp_packet.dest_port)
	    };

	    let connection_key = UdpConnectionKey {
                src_ip: client_ip,
                src_port: udp_packet.src_port,
           };


	    if let Some(connection) = map_guard.get_mut(&connection_key) {
		connection.last_active = Instant::now();

		let socket = &connection.socket;
		socket.send_to(payload_bytes, target).unwrap();

	    } else {
	 	let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
		socket.set_mark(255).unwrap();
		let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
		socket.bind(&addr.into()).unwrap();
		let std_socket: UdpSocket = socket.into();
	     	// let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
		let arc_socket = Arc::new(std_socket);

		let hashmap_for_thread = Arc::clone(&udp_hashmap);
		let socket_for_struct = Arc::clone(&arc_socket);
		let socket_for_thread = Arc::clone(&arc_socket);
		let key_for_thread = connection_key.clone();
		let tx_for_thread = tx_clone.clone();

		let udp_connection = UdpConnection {
		    socket: socket_for_struct,
		    last_active: Instant::now(),
		};
		map_guard.insert(connection_key, udp_connection);

		arc_socket.send_to(payload_bytes, target).unwrap();

		thread::spawn(move || { 
		    socket_for_thread.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

		    loop {
			let mut response = [0; 4096];

			match socket_for_thread.recv_from(&mut response) {
			   Ok((amount, src_addr)) => { 
			    let actual_payload = &response[..amount];

			    if let IpAddr::V4(ipv4) = src_addr.ip() {
			
			    let remote_ip_bytes = ipv4.octets();
			    let remote_port = src_addr.port();

			    let final_packet = Udp::make_reply_payload(
				actual_payload, 
				&key_for_thread,
				remote_ip_bytes,
				remote_port
				);

			    tx_for_thread.send(final_packet).unwrap();
			    println!("UDP Reply routed back to client!");
				}
			    }
			  Err(_) => {
			    let mut thread_map_guard = hashmap_for_thread.lock().unwrap();
			
			    if let Some(connection) = thread_map_guard.get_mut(&key_for_thread) {
				if connection.last_active.elapsed() < Duration::from_secs(60) {
					continue;
				    } else if connection.last_active.elapsed() >= Duration::from_secs(60)  {
					thread_map_guard.remove(&key_for_thread);
					break;
				    }
				} else {
				    break;
				}
			    }
			}
		    }		
		});
	
		
	    }
	}

	if parsed_packet.proto == 6 {
	   println!("Intercepted Tcp Request! Forging reply..");

	   let map_clone = Arc::clone(&hashmap);

    	   let mut client_ip = [0u8; 4];
    	   client_ip.copy_from_slice(&packet_data[12..16]);

    	   let mut server_ip = [0u8; 4];
    	   server_ip.copy_from_slice(&packet_data[16..20]);

	   let ip_header = &packet_data[..ip_header_length];

    	   let tcp_bytes = &packet_data[ip_header_length..total_length];
    	   let tcp_packet = Tcp::new(tcp_bytes);

	   let tcp_header_bytes_len = (tcp_bytes[12] >> 4) as usize * 4;
	   let incoming_ts = Tcp::extract_incoming_ts_val(tcp_bytes, tcp_header_bytes_len);

	   let connection_key = ConnectionKey {
		src_ip: client_ip,
	        src_port: tcp_packet.src_port,
   		dest_ip: server_ip,
    		dest_port: tcp_packet.dest_port,
	   };

    	   let payload_length = total_length - ip_header_length - (tcp_packet.header_len as usize);

	   let mut map_guard = map_clone.lock().unwrap();
	   let mut should_remove = false;

	   if let Some(connection) = map_guard.get_mut(&connection_key) {
		connection.last_active = Instant::now();

		if let Some(ts) = incoming_ts {
		    connection.last_client_ts = ts;
		}

		if tcp_packet.ack {

		    let incoming_ack = BigEndian::read_u32(&packet_data[ip_header_length + 8 .. ip_header_length + 12]);
		
		    connection.unacked_queue.retain(|packet| {
		    let diff = packet.expected_ack.wrapping_sub(tcp_packet.ack_num);
		    let keep = diff > 0 && diff < 0x80000000;

		    if !keep { 
			println!("Client ACKed packet! Removing from queue. (Client ACKed up to: {})", incoming_ack);
                    }    

		    keep
		  });
	        }

		println!("Existing connection found! Current state: {:?}", connection.state);
		
		if connection.state == TcpState::SynReceived && tcp_packet.ack == true {
			connection.state = TcpState::Established;
			let (tx, rx) = mpsc::channel::<Vec<u8>>();
			connection.upstream_tx = Some(tx);

			let ip_header_clone = packet_data[0..ip_header_length].to_vec();
			let tcp_header_clone = packet_data[ip_header_length..(ip_header_length + (tcp_packet.header_len as usize))].to_vec();
			let tun_tx = tx_clone.clone(); 
			let map_for_reader = Arc::clone(&hashmap); 
			let key_for_reader = connection_key.clone();
			let c_ip = client_ip;
			let s_ip = server_ip;
			let d_port = tcp_packet.dest_port;

			thread::spawn(move || {
			    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
	                    socket.set_mark(255).unwrap();

                            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(s_ip[0], s_ip[1], s_ip[2], s_ip[3])), d_port);
			    println!("Thread: Attempting to connect to real internet IP: {}", addr);
               		    socket.connect(&addr.into()).unwrap();
			    println!("Thread: Successfully connected!");
	
			    let mut std_socket: TcpStream = socket.into();
			    let mut cloned_socket = std_socket.try_clone().unwrap();

			    thread::spawn(move || {
				let mut buffer = [0u8; 8192];
				println!("Thread: Waiting to read from internet...");

				loop {
				    match cloned_socket.read(&mut buffer) {
					Ok(0) => {
					    println!("Remote server closed the connection.");
					    let mut map_guard = map_for_reader.lock().unwrap();
					    if let Some(connection) = map_guard.get_mut(&key_for_reader) {
						let new_tcp_segment = Tcp::make_reply(
						    &tcp_header_clone,
						    &s_ip,
						    &c_ip,
						    0x11, // FIN-ACK
						    connection.snd_next,
						    connection.rcv_next,
						    Some(connection.ts_clock),
    						    Some(connection.last_client_ts)
						);
						let mut final_packet = Vec::new();
						final_packet.extend_from_slice(&ip_header_clone);
						final_packet.extend_from_slice(&new_tcp_segment);

						let new_total_length = final_packet.len() as u16;
						BigEndian::write_u16(&mut final_packet[2..4], new_total_length);
						IPv4::make_reply(&mut final_packet[0..ip_header_clone.len()]);
						
						tun_tx.send(final_packet).unwrap();
						
						connection.snd_next = connection.snd_next.wrapping_add(1);
						connection.state = TcpState::FinWait;
					    }
                    			    break;
					}
					Ok(bytes_read) => {
					    let internet_data = &mut buffer[..bytes_read];
					    println!("Got {} bytes from the internet!", bytes_read);	
					    
					    let mut map_guard = map_for_reader.lock().unwrap();

					    if let Some(connection) = map_guard.get_mut(&key_for_reader) {

						for chunk in internet_data.chunks_mut(1400) {
					
					    	let new_tcp_segment =
                        				Tcp::make_reply_payload(
                              				&tcp_header_clone,
                                			&s_ip,
                                			&c_ip,
                                			0x18, // PSH-ACK
                                			connection.snd_next,
                                			connection.rcv_next,
                                			chunk,
							Some(connection.ts_clock),
    							Some(connection.last_client_ts)
                                			);

		                           	let tcp_header_length = (new_tcp_segment[12] >> 4) * 4;
		
                         		   	let mut final_packet = Vec::new();
                         		   	final_packet.extend_from_slice(&ip_header_clone);
                         		   	final_packet.extend_from_slice(&new_tcp_segment);

                         			let new_total_length = final_packet.len() as u16;
                         			BigEndian::write_u16(&mut final_packet[2..4], new_total_length);

                         			IPv4::make_reply(&mut final_packet[0..ip_header_clone.len()]);

                         		        connection.snd_next = connection.snd_next.wrapping_add((new_tcp_segment.len() - tcp_header_length as usize) as u32);

                         			let unacked_que = UnackedPacket {
                             			        expected_ack: connection.snd_next,
                             			        packed_bytes: final_packet.clone(),
                             				sent_at: Instant::now()
                         				}; 

                         			connection.unacked_queue.push_back(unacked_que);

                         			tun_tx.send(final_packet).unwrap();
						println!("Response sent for a chunk!");	
					       }
					    }
					}
					Err(e) => {
					    println!("Error reading from internet: {:?}", e);
					    break;	
					}
				    }
				}
			    });

		    	    loop {
				match rx.recv() {
				Ok(payload) => {
				println!("Thread: Writing {} bytes to the internet...", payload.len());
				std_socket.write_all(&payload).unwrap();
					}
				Err(_) => break,
				    }
				}
			});
		}	

		if connection.state == TcpState::Established && payload_length > 0 {
		        let incoming_seq = tcp_packet.seq_num;

			let seq_diff = incoming_seq.wrapping_sub(connection.rcv_next);

			if seq_diff > 0 && seq_diff > 0x80000000 {
			    println!("Retransmission detected! Re-sending existing ACK: {}", connection.rcv_next);
			} else {
			println!("Got your data!");

			connection.rcv_next = connection.rcv_next.wrapping_add(payload_length as u32);

			let header_length = ip_header_length + (tcp_packet.header_len as usize);

			if let Some(tx) = &connection.upstream_tx {
			    tx.send(packet_data[header_length..total_length].to_vec()).unwrap();
			}
			

			let new_tcp_segment = Tcp::make_reply(
                            &packet_data[ip_header_length..total_length],
                            &server_ip,
                            &client_ip,
                            0x10, // ACK
                            connection.snd_next,
                            connection.rcv_next,
			    Some(connection.ts_clock),
    			    Some(connection.last_client_ts)
                            );

			let mut final_packet = Vec::new();
                        final_packet.extend_from_slice(&packet_data[0..ip_header_length]);
                        final_packet.extend_from_slice(&new_tcp_segment);

                        let new_total_length = final_packet.len() as u16;
                        BigEndian::write_u16(&mut final_packet[2..4], new_total_length);

                        IPv4::make_reply(&mut final_packet[0..ip_header_length]);

                        tx_clone.send(final_packet).unwrap();
			
			}

			/*
			connection.rcv_next += payload_length as u32;

			let payload_length = tcp_packet.header_len as usize + ip_header_length;
		
			let payload = &packet_data[payload_length..total_length];	

			let string = String::from_utf8_lossy(payload);
	
			println!("Incoming HTTP Request:\n {}", string);

			let new_string = match string {
			    s if s.starts_with("GET / HTTP/1.1") => {
				    String::from("HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nHello my friend!")
			         }
			    s if s.starts_with("GET /secret") => {
				    String::from("HTTP/1.1 200 OK\r\nContent-Length: 67\r\n\r\nHow did you end up getting there? \nGet out! You shouldn't be there!")
				}
			    _ => String::from("HTTP/1.1 404 Not Found\r\nContent-Length: 15\r\n\r\nPage not found!")
			};
	
			let new_tcp_segment =
                 	Tcp::make_reply_payload(
                     		&packet_data[ip_header_length..total_length],
                     		&server_ip,
                    		&client_ip,
                     		0x18, // PSH-ACK
				connection.snd_next,
				connection.rcv_next,
				new_string.as_bytes()
        			);

			 let tcp_header_length = (new_tcp_segment[12] >> 4) * 4;

          		 let mut final_packet = Vec::new();
           		 final_packet.extend_from_slice(&packet_data[0..ip_header_length]);
          		 final_packet.extend_from_slice(&new_tcp_segment);

          		 let new_total_length = final_packet.len() as u16;
          		 BigEndian::write_u16(&mut final_packet[2..4], new_total_length);

          		 IPv4::make_reply(&mut final_packet[0..ip_header_length]);
			
			 connection.snd_next += (new_tcp_segment.len() - tcp_header_length as usize) as u32;

			 let unacked_que = UnackedPacket {
			     expected_ack: connection.snd_next,
			     packed_bytes: final_packet.clone(),
			     sent_at: Instant::now()				
			 }; 
		
			 connection.unacked_queue.push_back(unacked_que);
			
           		 tx_clone.send(final_packet).unwrap();
        	         println!("HTTP Response sent!");
	
	 		*/
		}

		if tcp_packet.fin && connection.state == TcpState::Established {
		    println!("FIN received! Closing connection...");

		    connection.rcv_next += 1;

		    let new_tcp_segment = Tcp::make_reply(
          		  &packet_data[ip_header_length..total_length],
           		  &server_ip,
            		  &client_ip,
           		  0x11, // FIN-ACK
            		  connection.snd_next,
            		  connection.rcv_next,
			  Some(connection.ts_clock),
    			  Some(connection.last_client_ts)
        		);

		    let mut final_packet = Vec::new();
   		    final_packet.extend_from_slice(&packet_data[0..ip_header_length]);
 		    final_packet.extend_from_slice(&new_tcp_segment);

   		    let new_total_length = final_packet.len() as u16;
   	            BigEndian::write_u16(&mut final_packet[2..4], new_total_length);

	            IPv4::make_reply(&mut final_packet[0..ip_header_length]);
    
   		    tx_clone.send(final_packet).unwrap();

  	       	    println!("FIN-ACK sent! Waiting for final ACK..");
    		   
		    connection.state = TcpState::LastAck;
		    should_remove = false;
		}

		else if connection.state == TcpState::LastAck {
		    if tcp_packet.ack {
			println!("Final ACK received from client. Safe to destroy connection!");
			connection.state = TcpState::Closed;
			should_remove = true;
	  	    }
		}

	 	else if connection.state == TcpState::FinWait {
		    if tcp_packet.ack {
			println!("Client acknowledged our FIN. Connection teardown complete!");
        		connection.state = TcpState::Closed;
        		should_remove = true;
		    }
		    
		    if tcp_packet.fin {
			println!("Client also sent FIN. Replying with ACK...");
			connection.rcv_next = connection.rcv_next.wrapping_add(1);

        		let final_ack_segment = Tcp::make_reply(
            			&packet_data[ip_header_length..total_length],
            			&server_ip,
            			&client_ip,
            			0x10, // ACK
            			connection.snd_next,
            			connection.rcv_next,
            			Some(connection.ts_clock),
            			Some(connection.last_client_ts)
        			);

        		let mut final_packet = Vec::new();
        		final_packet.extend_from_slice(&packet_data[0..ip_header_length]);
        		final_packet.extend_from_slice(&final_ack_segment);

        		let new_total_length = final_packet.len() as u16;
        		BigEndian::write_u16(&mut final_packet[2..4], new_total_length);
        		IPv4::make_reply(&mut final_packet[0..ip_header_length]);

        		tx_clone.send(final_packet).unwrap();
        		should_remove = true;
		    }			
		}
	
		if should_remove {
		   map_guard.remove(&connection_key);
        	   println!("Connection successfully closed and removed from HashMap!");
		}

	  } else {
	      if tcp_packet.syn && !tcp_packet.ack {
		    println!("New SYN received! Creating connection folder...");

		    let isn = 1u32;

		    let starting_clock = 1000;
		    let client_ts = incoming_ts.unwrap_or(0);

                    let new_tcp_segment = Tcp::make_reply(
	                    &packet_data[ip_header_length..total_length],
        	            &server_ip,
                	    &client_ip,
                  	    0x12, // SYN-ACK
			    isn,
			    tcp_packet.seq_num + 1,
			    Some(starting_clock),
    			    Some(client_ts)
        		    );
		

		      let mut final_packet = Vec::new();
    
   		      final_packet.extend_from_slice(&packet_data[0..ip_header_length]);
		      final_packet.extend_from_slice(&new_tcp_segment);

   		      let new_total_length = final_packet.len() as u16;
		      BigEndian::write_u16(&mut final_packet[2..4], new_total_length);

   		      IPv4::make_reply(&mut final_packet[0..ip_header_length]);
    
    		      tx_clone.send(final_packet).unwrap();
   		      println!("SYN-ACK sent!");		      

		      let new_connection = Connection {
                          state: TcpState::SynReceived,
                          snd_next: 2,
                          rcv_next: tcp_packet.seq_num + 1,
			  last_active: Instant::now(),
			  unacked_queue: VecDeque::new(),
			  upstream_tx: None,
			  last_client_ts: client_ts,
			  ts_clock: starting_clock,
                        };

                     map_guard.insert(connection_key, new_connection);
		
		} else {
        	     println!("Unknown packet for a non-existent connection. Sending RST...");
		     
	   	     let tcp_header_length = (packet_data[ip_header_length + 12] >> 4) as usize * 4;
		     let tcp_payload_len = total_length - ip_header_length - tcp_header_length;

		     let mut rcv_next = tcp_packet.seq_num.wrapping_add(tcp_payload_len as u32);

		     if tcp_payload_len == 0 && (tcp_packet.syn || tcp_packet.fin) {
			rcv_next = rcv_next.wrapping_add(1);
		     }	
		     
		     let client_ts = incoming_ts.unwrap_or(0);

		     let rst_tcp_segment = Tcp::make_reply(
						&packet_data[ip_header_length..total_length],
						&server_ip,
						&client_ip,
						0x14, // RST-ACK
						tcp_packet.ack_num,
						rcv_next,
						Some(0),
    						Some(client_ts)
						);
			
		     let mut final_packet = Vec::new();
		     final_packet.extend_from_slice(&packet_data[0..ip_header_length]);
		     final_packet.extend_from_slice(&rst_tcp_segment);
		
		     let new_total_length = final_packet.len() as u16;
		     BigEndian::write_u16(&mut final_packet[2..4], new_total_length);

		     IPv4::make_reply(&mut final_packet[0..ip_header_length]);

		     tx_clone.send(final_packet).unwrap();
	     }
	  }       
    }
  }
}
