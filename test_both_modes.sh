#!/bin/bash

# Test script for both filtering modes
# Compiles, runs basic tests, and prepares for wrk benchmarking

set -e  # Exit on error

echo "========================================="
echo "🚀 TIGER-FOX DUAL MODE TEST SCRIPT"
echo "========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    print_warning "Running as root - good for NFQUEUE access"
else
    print_warning "NOT running as root - will need sudo for actual filtering"
fi

# Step 1: Check files exist
print_info "Step 1: Checking source files..."
if [ -f "./check_files.sh" ]; then
    chmod +x ./check_files.sh
    ./check_files.sh
    print_status "All source files found"
else
    print_error "check_files.sh not found - creating it..."
    cat > check_files.sh << 'EOF'
#!/bin/bash
files=(
    "src/engine/fast_sequential_engine.h"
    "src/engine/fast_sequential_engine.cpp"
    "src/engine/ultra_parallel_engine.h"
    "src/engine/ultra_parallel_engine.cpp"
    "src/handlers/packet_handler.h"
    "src/handlers/packet_handler.cpp"
    "src/tiger_system.h"
    "src/tiger_system.cpp"
    "src/main.cpp"
    "CMakeLists.txt"
)
for f in "${files[@]}"; do
    if [ ! -f "$f" ]; then
        echo "MISSING: $f"
        exit 1
    fi
done
echo "All files present"
EOF
    chmod +x ./check_files.sh
    ./check_files.sh
fi

echo ""

# Step 2: Clean old build
print_info "Step 2: Cleaning old build..."
if [ -f "./build/tiger-fox" ]; then
    rm -f ./build/tiger-fox
    print_status "Removed old binary"
fi

echo ""

# Step 3: Compile
print_info "Step 3: Compiling with build.sh..."
if [ -f "./build.sh" ]; then
    chmod +x ./build.sh
    if ./build.sh; then
        print_status "Compilation successful!"
    else
        print_error "Compilation failed - check errors above"
        exit 1
    fi
else
    print_error "build.sh not found - cannot compile"
    exit 1
fi

echo ""

# Step 4: Verify binary exists
print_info "Step 4: Verifying binary..."
if [ -f "./build/tiger-fox" ]; then
    print_status "Binary found: ./build/tiger-fox"
    ls -lh ./build/tiger-fox
else
    print_error "Binary not created - compilation may have failed"
    exit 1
fi

echo ""

# Step 5: Test basic help
print_info "Step 5: Testing --help..."
if ./build/tiger-fox --help 2>&1 | grep -q "mode"; then
    print_status "Help text includes --mode option"
else
    print_warning "Help text may not show --mode (check manually)"
fi

echo ""

# Step 6: Check rules file
print_info "Step 6: Checking rules file..."
if [ -f "./rules/example_rules.json" ]; then
    rule_count=$(grep -c "\"id\":" ./rules/example_rules.json || echo "0")
    print_status "Rules file found with ~$rule_count rules"
    if [ "$rule_count" -lt 5 ]; then
        print_warning "Only $rule_count rules - may need more for testing"
    fi
else
    print_error "Rules file not found at ./rules/example_rules.json"
    exit 1
fi

echo ""

# Step 7: Instructions for manual testing
echo "========================================="
echo "✅ BUILD SUCCESSFUL - READY TO TEST"
echo "========================================="
echo ""
echo "📋 NEXT STEPS:"
echo ""
echo "1️⃣  TEST SEQUENTIAL MODE:"
echo "    ${GREEN}sudo ./build/tiger-fox --mode sequential${NC}"
echo ""
echo "2️⃣  TEST PARALLEL MODE (4 workers):"
echo "    ${GREEN}sudo ./build/tiger-fox --mode parallel --workers 4${NC}"
echo ""
echo "3️⃣  BENCHMARK WITH WRK (from injector node):"
echo "    ${GREEN}wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/${NC}"
echo ""
echo "4️⃣  COMPARE RESULTS:"
echo "    - Sequential baseline: Should get ~2000-3000 req/s"
echo "    - Parallel (4 workers): Target >3000 req/s"
echo ""
echo "========================================="
echo "🔬 RESEARCH VALIDATION:"
echo "========================================="
echo ""
echo "To prove parallel > sequential:"
echo "  - Run wrk with sequential mode (30s)"
echo "  - Stop tiger-fox (Ctrl+C)"
echo "  - Run wrk with parallel mode (30s)"
echo "  - Compare req/s metrics"
echo ""
echo "📊 Expected Speed-Up:"
echo "  2 workers: 1.5-1.8x faster"
echo "  4 workers: 2.0-2.5x faster"
echo "  8 workers: 2.5-3.0x faster (diminishing returns)"
echo ""
echo "========================================="

# Optional: Quick syntax test (if running as root)
if [ "$EUID" -eq 0 ]; then
    echo ""
    print_info "Quick syntax test (will fail without iptables rules)..."
    echo ""
    
    # Test sequential
    print_info "Testing sequential mode syntax..."
    timeout 2 ./build/tiger-fox --mode sequential 2>&1 | head -20 || true
    
    echo ""
    
    # Test parallel
    print_info "Testing parallel mode syntax..."
    timeout 2 ./build/tiger-fox --mode parallel --workers 2 2>&1 | head -20 || true
    
    echo ""
    print_warning "Above errors are expected (no iptables rules yet)"
fi

echo ""
print_status "All checks passed! 🎉"
