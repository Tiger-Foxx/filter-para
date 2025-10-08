#!/bin/bash
# =============================================================================
# CloudLab Filter Node Setup Script
# =============================================================================
# This script configures the middle node as a network filter between
# injector (10.10.1.10) and server (10.10.2.20)
# =============================================================================

set -e

echo "🔧 CloudLab Filter Node Setup"
echo "========================================"

# =============================================================================
# 1. ENABLE IP FORWARDING
# =============================================================================
echo ""
echo "📡 Step 1: Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf > /dev/null
echo "✅ IP forwarding enabled"

# =============================================================================
# 2. DETECT NETWORK INTERFACES
# =============================================================================
echo ""
echo "🔍 Step 2: Detecting network interfaces..."

# Interface connected to injector (10.10.1.x network)
IFACE_INJECTOR=$(ip route | grep "10.10.1.0/24" | awk '{print $3}')

# Interface connected to server (10.10.2.x network)
IFACE_SERVER=$(ip route | grep "10.10.2.0/24" | awk '{print $3}')

if [ -z "$IFACE_INJECTOR" ] || [ -z "$IFACE_SERVER" ]; then
    echo "❌ Error: Could not detect network interfaces"
    echo "   Please check your network configuration"
    ip addr show
    exit 1
fi

echo "✅ Detected interfaces:"
echo "   • Injector side: $IFACE_INJECTOR (10.10.1.x)"
echo "   • Server side:   $IFACE_SERVER (10.10.2.x)"

# =============================================================================
# 3. FLUSH EXISTING IPTABLES RULES
# =============================================================================
echo ""
echo "🧹 Step 3: Flushing existing iptables rules..."
sudo iptables -F
sudo iptables -F FORWARD
sudo iptables -F INPUT
sudo iptables -F OUTPUT
sudo iptables -t nat -F
sudo iptables -t mangle -F
echo "✅ Iptables flushed"

# =============================================================================
# 4. SET DEFAULT POLICIES
# =============================================================================
echo ""
echo "🔒 Step 4: Setting default policies..."
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
echo "✅ Default policies set to ACCEPT"

# =============================================================================
# 5. CONFIGURE NFQUEUE RULES
# =============================================================================
echo ""
echo "🎯 Step 5: Configuring NFQUEUE rules..."

# Traffic from injector to server → NFQUEUE (filtering)
sudo iptables -A FORWARD -i $IFACE_INJECTOR -o $IFACE_SERVER -j NFQUEUE --queue-num 0

# Return traffic from server to injector → ACCEPT (no filtering)
sudo iptables -A FORWARD -i $IFACE_SERVER -o $IFACE_INJECTOR -j ACCEPT

echo "✅ NFQUEUE rules configured"

# =============================================================================
# 6. VERIFY CONFIGURATION
# =============================================================================
echo ""
echo "🔍 Step 6: Verifying configuration..."
echo ""
echo "IP Forwarding:"
sysctl net.ipv4.ip_forward

echo ""
echo "Network Interfaces:"
ip addr show $IFACE_INJECTOR | grep "inet "
ip addr show $IFACE_SERVER | grep "inet "

echo ""
echo "Iptables FORWARD chain:"
sudo iptables -L FORWARD -n -v --line-numbers

echo ""
echo "Routing table:"
ip route

# =============================================================================
# 7. TEST CONNECTIVITY (optional)
# =============================================================================
echo ""
echo "🧪 Step 7: Testing connectivity..."

echo "   • Ping server from filter node:"
if ping -c 2 -W 2 10.10.2.20 > /dev/null 2>&1; then
    echo "     ✅ Server reachable (10.10.2.20)"
else
    echo "     ⚠️  Server not reachable (10.10.2.20)"
fi

echo "   • Ping injector from filter node:"
if ping -c 2 -W 2 10.10.1.10 > /dev/null 2>&1; then
    echo "     ✅ Injector reachable (10.10.1.10)"
else
    echo "     ⚠️  Injector not reachable (10.10.1.10)"
fi

# =============================================================================
# DONE
# =============================================================================
echo ""
echo "========================================"
echo "✅ Filter node setup complete!"
echo "========================================"
echo ""
echo "📋 Summary:"
echo "   • IP forwarding: ENABLED"
echo "   • Injector interface: $IFACE_INJECTOR"
echo "   • Server interface: $IFACE_SERVER"
echo "   • NFQUEUE: queue 0 on FORWARD chain"
echo ""
echo "🚀 Ready to start tiger-fox:"
echo "   sudo ./build/tiger-fox --rules rules/example_rules.json --verbose"
echo ""
echo "🧪 Test from injector node:"
echo "   ping 10.10.2.20"
echo "   curl http://10.10.2.20/"
echo ""
