#!/bin/bash
# Tiger-Fox C++ Dependencies Installation Script
# Ubuntu 20.04+ required

set -e

echo "🔧 Installing Tiger-Fox C++ dependencies..."

# System packages
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    libnetfilter-queue-dev \
    libnetfilter-queue1 \
    nlohmann-json3-dev \
    libpcre2-dev \
    libpcre2-8-0 \
    iptables-persistent \
    net-tools \
    git

# Verify installations
echo "📋 Verifying installations..."

# Check compiler
echo "GCC version:"
g++ --version | head -1

echo "CMake version:"
cmake --version | head -1

# Check libraries
if pkg-config --exists libnetfilter_queue; then
    echo "✅ libnetfilter_queue found: $(pkg-config --modversion libnetfilter_queue)"
else
    echo "❌ libnetfilter_queue missing"
    exit 1
fi

if pkg-config --exists libpcre2-8; then
    echo "✅ libpcre2 found: $(pkg-config --modversion libpcre2-8)"
else
    echo "❌ libpcre2 missing"
    exit 1
fi

# Check nlohmann-json
if [ -f /usr/include/nlohmann/json.hpp ]; then
    echo "✅ nlohmann-json found"
elif [ -f /usr/local/include/nlohmann/json.hpp ]; then
    echo "✅ nlohmann-json found (local)"
else
    echo "❌ nlohmann-json missing"
    echo "Installing nlohmann-json manually..."
    
    # Fallback installation
    cd /tmp
    wget https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
    sudo mkdir -p /usr/local/include/nlohmann
    sudo mv json.hpp /usr/local/include/nlohmann/
    echo "✅ nlohmann-json installed manually"
fi

echo ""
echo "🎯 All dependencies installed successfully!"
echo ""
echo "Next steps:"
echo "1. Run: chmod +x build.sh"
echo "2. Run: ./build.sh"
echo "3. Test: sudo ./build/tiger-fox --help"
echo ""
echo "For CloudLab setup:"
echo "- Make sure you have root access"
echo "- Enable IP forwarding: sudo sysctl -w net.ipv4.ip_forward=1"
echo "- Configure iptables FORWARD rules (done automatically by tiger-fox)"