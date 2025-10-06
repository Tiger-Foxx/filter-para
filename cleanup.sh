#!/bin/bash
# Tiger-Fox NFQUEUE Cleanup Script
# Run this if the program crashes and leaves NFQUEUE locked

echo "🧹 Cleaning up stale NFQUEUE connections..."

# Kill any existing tiger-fox processes
PIDS=$(pgrep -f tiger-fox)
if [ -n "$PIDS" ]; then
    echo "   Found running processes: $PIDS"
    echo "   Killing..."
    sudo kill -9 $PIDS 2>/dev/null
    sleep 1
fi

# Flush NFQUEUE
echo "   Flushing NFQUEUE..."
sudo rmmod nfnetlink_queue 2>/dev/null
sudo modprobe nfnetlink_queue

# Remove iptables rules
echo "   Removing iptables rules..."
sudo iptables -D FORWARD -i eno2 -o enp5s0f0 -j ACCEPT 2>/dev/null
sudo iptables -D FORWARD -i enp5s0f0 -o eno2 -j NFQUEUE --queue-num 0 2>/dev/null

# List remaining rules
echo ""
echo "📋 Current iptables FORWARD rules:"
sudo iptables -L FORWARD -n -v

echo ""
echo "✅ Cleanup complete! You can now restart tiger-fox"
