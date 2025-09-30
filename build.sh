#!/bin/bash
# Tiger-Fox C++ Build Script
# High-performance network filtering system

set -e

PROJECT_NAME="tiger-fox"
BUILD_TYPE=${1:-Release}  # Release or Debug
JOBS=${2:-$(nproc)}       # Number of parallel jobs

echo "🔨 Building Tiger-Fox C++ Network Filtering System"
echo "========================================================"
echo "Build type: $BUILD_TYPE"
echo "Parallel jobs: $JOBS"
echo "========================================================"

# Create build directory
mkdir -p build
cd build

# Configure with CMake
echo "🔧 Configuring with CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DENABLE_OPTIMIZATIONS=ON

# Build
echo "🔨 Building project..."
make -j$JOBS

echo ""
echo "✅ Build completed successfully!"
echo ""

# Display build info
echo "📋 Build Information:"
echo "Executable: build/$PROJECT_NAME"
echo "Size: $(ls -lh $PROJECT_NAME | awk '{print $5}')"

# Display dependencies
echo ""
echo "🔗 Dependencies check:"
ldd $PROJECT_NAME | grep -E "(netfilter|pcre|json)" || true

echo ""
echo "🚀 Ready to run!"
echo ""
echo "Usage examples:"
echo "  sudo ./build/$PROJECT_NAME --sequential"
echo "  sudo ./build/$PROJECT_NAME --hybrid --workers 8"
echo "  sudo ./build/$PROJECT_NAME --sequential-hyb"
echo "  sudo ./build/$PROJECT_NAME --help"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Note: $PROJECT_NAME requires root privileges for NFQUEUE access"
    echo "   Run with: sudo ./build/$PROJECT_NAME [options]"
fi

echo "🌐 CloudLab Architecture:"
echo "  injector (10.10.1.10) → filter (this machine) → server (10.10.2.20)"
echo ""
echo "📊 Test with wrk from injector:"
echo "  wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/"