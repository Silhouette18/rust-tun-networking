#!/bin/bash
# Run this once with sudo

ip rule del fwmark 255 table main 2>/dev/null
ip rule del table 100 2>/dev/null
ip route flush table 100 2>/dev/null

ip route add default dev tun0 table 100

ip rule add fwmark 255 table main prio 32764

ip rule add table 100 prio 32765

echo "Universal transparent proxy routing enabled!"
