# rust-net-stack

A user-space TCP/IP stack and transparent network proxy, written in Rust from scratch. It reads raw IPv4 packets off a TUN device, terminates ICMP, UDP, and TCP itself, re-originates each connection to its real destination over a normal OS socket, and translates the response back. Ordinary applications on the machine can be transparently routed through it with no client-side configuration.

## How it works

1. `tun0` is created and assigned `10.0.0.1/24`. It behaves like a virtual network interface, except its "wire" is this program instead of a physical NIC.
2. `setup_routing.sh` installs Linux policy routing that sends the machine's outbound traffic through `tun0` by default, while exempting anything carrying `fwmark 255` (see step 4) so the proxy's own outbound traffic doesn't loop back into itself.
3. The main loop reads raw IPv4 packets from `tun0` and dispatches on the protocol field:
   - **ICMP** Echo Requests are answered directly: the stack forges the Echo Reply itself rather than forwarding it anywhere.
   - **UDP** packets get a real `UdpSocket` opened to their destination (DNS on port 53 is redirected to `8.8.8.8` first). A background thread waits for the reply, relays it back into `tun0`, and tears the socket down after roughly a minute of inactivity.
   - **TCP** packets are tracked in a small state machine (`SynReceived` → `Established` → `FinWait` / `LastAck` → `Closed`). Once the handshake completes, a real `TcpStream` is opened to the true destination and application data is proxied in both directions, with sequence numbers, ACKs, and retransmission handled by hand. Packets that don't match any known connection or in-progress handshake get an RST in reply.
4. Every "real" socket the stack opens is tagged with `SO_MARK 255`. That's the mark step 2's routing rule checks for to send that traffic out normally instead of back into `tun0`.
5. Two background threads keep things tidy: a sweeper drops TCP connections idle for more than about a minute, and a retransmitter resends the oldest unacked TCP segment on a connection if it's gone unacknowledged for more than 500ms.

## Features

- Hand-rolled IPv4, ICMP, UDP, and TCP parsing/serialization, including proper Internet checksums
- Full TCP three-way handshake, data transfer, retransmission, and graceful teardown, including simultaneous-close handling
- TCP timestamp option (RFC 7323) support: incoming timestamps are captured and echoed back
- Transparent DNS interception: all port-53 traffic is redirected to `8.8.8.8`
- Automatic cleanup of idle TCP and UDP connections
- System-wide transparent proxying via Linux policy routing, with no per-application configuration needed

## Requirements

- Linux (uses TUN devices, `SO_MARK`, and `ip` policy routing; this won't run on macOS or Windows)
- Rust toolchain (`cargo`)
- `iproute2` (the `ip` command)
- Root privileges: creating the TUN device and marking sockets both require elevated permissions
- Crates: `tun-tap`, `byteorder`, `bytes`, `socket2` (see `Cargo.toml` for exact versions)

## Project structure

- `src/main.rs` — entry point; wires up the modules and starts the stack
- `src/tun.rs` — creates and configures `tun0`; contains the main packet loop, the TCP/UDP connection tables, and the background sweeper/retransmit threads
- `src/ipv4.rs` — IPv4 header parsing, the address-swap helper used when building replies, and the shared Internet checksum routine
- `src/icmp.rs` — ICMP parsing and Echo Reply forging
- `src/udp.rs` — UDP header parsing, connection key/state types, and reply-packet construction (also includes a couple of DNS-specific helpers not currently wired into the live packet path)
- `src/tcp.rs` — TCP header parsing, the connection state machine and its types, reply-segment construction, and TCP timestamp option handling
- `setup_routing.sh` — installs the policy-routing rules described above
- `cleanup_routing.sh` — removes those rules and deletes `tun0`
- `run.sh` — builds the project and runs it with `sudo`

## Getting started

```bash
# 1. Build and start the stack (creates and brings up tun0)
./run.sh

# 2. In a second terminal, enable transparent capture for the whole machine
sudo ./setup_routing.sh

# 3. Traffic from this machine now flows through the stack
ping 1.1.1.1
curl https://example.com
dig example.com          # DNS is transparently redirected to 8.8.8.8

# 4. When you're done, stop the binary (Ctrl+C) and restore normal routing
sudo ./cleanup_routing.sh
```

> **Heads up:** `setup_routing.sh` redirects *all* outbound traffic on the machine through the stack by default. If you're testing this over SSH on a remote box, make sure you have an out-of-band way back in before enabling it, in case something along the TCP/UDP path misbehaves and drops your session.

## Known limitations

This is a from-scratch implementation, so a few things are simplified or still rough:

- Error handling leans heavily on `.unwrap()`, so a malformed or unusual packet can currently crash the process instead of being dropped gracefully
- TCP initial sequence numbers are fixed rather than randomized, and the timestamp value sent to peers is static rather than incrementing
- Options like window scaling and SACK are copied through from the peer's own header rather than actually being negotiated
- Retransmission is a fixed 500ms timer on the oldest unacked segment per connection, with no exponential backoff or real congestion control
- UDP connections are keyed only by the client's `(IP, port)`, not by destination, so one client port talking to two different UDP destinations at once will share a single outbound socket
- ICMP Echo Requests are answered locally rather than actually forwarded to and relayed from the real destination
- DNS (port 53) is unconditionally redirected to `8.8.8.8`, regardless of what resolver the client believes it's using
