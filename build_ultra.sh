#!/bin/bash

# 🚀 Build TIGER-FOX ULTRA (Single-threaded, Zero-Copy, Lock-Free)

set -e

echo "=========================================="
echo "🚀 TIGER-FOX ULTRA BUILD"
echo "=========================================="
echo ""

# Create build directory
mkdir -p build
cd build

echo "🔧 Configuring CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

echo ""
echo "🔨 Building ULTRA FAST version..."
make tiger-fox-ultra -j$(nproc)

echo ""
if [ -f "tiger-fox-ultra" ]; then
    echo "✅ Build completed successfully!"
    echo ""
    echo "📋 Build Information:"
    echo "Executable: build/tiger-fox-ultra"
    ls -lh tiger-fox-ultra | awk '{print "Size: " $5}'
    echo ""
    echo "🚀 Ready to run!"
    echo ""
    echo "Usage:"
    echo "  sudo ./build/tiger-fox-ultra --verbose"
    echo "  sudo ./build/tiger-fox-ultra --help"
    echo ""
    echo "⚠️  Note: tiger-fox-ultra requires root privileges for NFQUEUE access"
    echo "   Run with: sudo ./build/tiger-fox-ultra [options]"
else
    echo "❌ Build failed!"
    exit 1
fi
