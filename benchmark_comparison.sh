#!/bin/bash

# 📊 BENCHMARK COMPARISON: Original vs ULTRA FAST

echo "=========================================="
echo "📊 TIGER-FOX BENCHMARK COMPARISON"
echo "=========================================="
echo ""

# Clean previous processes
echo "🧹 Cleaning previous processes..."
sudo pkill -9 tiger-fox 2>/dev/null || true
sleep 1

# ============================================================
# TEST 1: ULTRA FAST MODE
# ============================================================
echo ""
echo "=========================================="
echo "🚀 TEST 1: ULTRA FAST MODE"
echo "=========================================="

if [ ! -f "build/tiger-fox-ultra" ]; then
    echo "❌ build/tiger-fox-ultra not found! Run ./build_ultra.sh first"
    exit 1
fi

echo "Starting ULTRA FAST mode..."
sudo ./build/tiger-fox-ultra &
ULTRA_PID=$!
echo "PID: $ULTRA_PID"

echo "Waiting 3 seconds for startup..."
sleep 3

echo ""
echo "Running benchmark (30 seconds)..."
wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/ 2>&1 | tee benchmark_ultra.txt

echo ""
echo "Stopping ULTRA FAST..."
sudo pkill -SIGINT tiger-fox-ultra
sleep 2

# ============================================================
# TEST 2: ORIGINAL MODE (if exists)
# ============================================================
if [ -f "build/tiger-fox" ]; then
    echo ""
    echo "=========================================="
    echo "👥 TEST 2: ORIGINAL MODE (8 workers)"
    echo "=========================================="
    
    echo "Starting ORIGINAL mode..."
    sudo ./build/tiger-fox --workers 8 &
    ORIGINAL_PID=$!
    echo "PID: $ORIGINAL_PID"
    
    echo "Waiting 3 seconds for startup..."
    sleep 3
    
    echo ""
    echo "Running benchmark (30 seconds)..."
    wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/ 2>&1 | tee benchmark_original.txt
    
    echo ""
    echo "Stopping ORIGINAL..."
    sudo pkill -SIGINT tiger-fox
    sleep 2
fi

# ============================================================
# RESULTS COMPARISON
# ============================================================
echo ""
echo "=========================================="
echo "📊 RESULTS COMPARISON"
echo "=========================================="

echo ""
echo "🚀 ULTRA FAST MODE:"
echo "-------------------"
grep "Requests/sec:" benchmark_ultra.txt
grep "Latency" benchmark_ultra.txt | head -n 4

if [ -f "benchmark_original.txt" ]; then
    echo ""
    echo "👥 ORIGINAL MODE (8 workers):"
    echo "-----------------------------"
    grep "Requests/sec:" benchmark_original.txt
    grep "Latency" benchmark_original.txt | head -n 4
    
    # Calculate improvement
    ULTRA_RPS=$(grep "Requests/sec:" benchmark_ultra.txt | awk '{print $2}')
    ORIGINAL_RPS=$(grep "Requests/sec:" benchmark_original.txt | awk '{print $2}')
    
    if [ ! -z "$ULTRA_RPS" ] && [ ! -z "$ORIGINAL_RPS" ]; then
        IMPROVEMENT=$(echo "scale=2; ($ULTRA_RPS / $ORIGINAL_RPS - 1) * 100" | bc)
        echo ""
        echo "📈 IMPROVEMENT: ${IMPROVEMENT}%"
    fi
fi

echo ""
echo "✅ Benchmark complete!"
echo ""
echo "📁 Results saved:"
echo "   • benchmark_ultra.txt"
if [ -f "benchmark_original.txt" ]; then
    echo "   • benchmark_original.txt"
fi
