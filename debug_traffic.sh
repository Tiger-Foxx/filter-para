#!/bin/bash

# 🔍 DEBUG: Capture 100 premiers paquets pour analyser

echo "🔍 Capturing 100 packets to analyze traffic patterns..."

sudo tcpdump -i enp5s0f0 -c 100 -nn 'tcp' 2>&1 | head -n 110

echo ""
echo "📊 ANALYSIS:"
echo "============"

# Count SYN packets
SYN_COUNT=$(sudo tcpdump -i enp5s0f0 -c 100 -nn 'tcp[tcpflags] & tcp-syn != 0' 2>&1 | grep -c "Flags \[S")
echo "SYN packets: $SYN_COUNT"

# Count ACK packets  
ACK_COUNT=$(sudo tcpdump -i enp5s0f0 -c 100 -nn 'tcp[tcpflags] & tcp-ack != 0' 2>&1 | grep -c "Flags \[")
echo "ACK packets: $ACK_COUNT"

# Count packets with data
DATA_COUNT=$(sudo tcpdump -i enp5s0f0 -c 100 -nn 'tcp and greater 60' 2>&1 | grep -c ">")
echo "Packets with data (>60 bytes): $DATA_COUNT"

echo ""
echo "✅ Done"
