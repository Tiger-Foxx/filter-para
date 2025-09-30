#!/bin/bash
# Tiger-Fox C++ Build Script
# High-performance hybrid network filtering system

set -e

PROJECT_NAME="tiger-fox"
BUILD_TYPE=${1:-Release}
JOBS=${2:-$(nproc)}

echo "🔨 Building Tiger-Fox C++ Hybrid Filtering System"
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
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

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

echo ""
echo "🚀 Ready to run!"
echo ""
echo "Usage:"
echo "  sudo ./build/$PROJECT_NAME --workers 8"
echo "  sudo ./build/$PROJECT_NAME --help"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Note: $PROJECT_NAME requires root privileges for NFQUEUE access"
    echo "   Run with: sudo ./build/$PROJECT_NAME [options]"
fi
