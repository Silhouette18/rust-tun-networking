#!/bin/bash
# Run with sudo

echo "Cleaning up proxy routing rules..."

ip rule del fwmark 255 table main 2>/dev/null
ip rule del table 100 2>/dev/null

ip route flush table 100 2>/dev/null

ip link delete tun0 2>/dev/null

echo "Network restored to normal!"
