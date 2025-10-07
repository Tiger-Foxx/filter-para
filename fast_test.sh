#!/bin/bash

# 🚀 FAST TEST - Mesure performance baseline

echo "==================================="
echo "🧹 CLEANING OLD PROCESSES"
echo "==================================="

sudo pkill -9 tiger-fox 2>/dev/null || true
sleep 1

echo ""
echo "==================================="
echo "🚀 STARTING FILTER (NO TCP REASSEMBLY)"
echo "==================================="

cd /home/fox/filter-para
sudo ./build/tiger-fox --workers 8 --verbose &

FILTER_PID=$!
echo "Filter PID: $FILTER_PID"

echo ""
echo "==================================="
echo "⏳ WAITING 3 SECONDS FOR STARTUP"
echo "==================================="
sleep 3

echo ""
echo "==================================="
echo "🔥 BENCHMARK (30 seconds)"
echo "==================================="

wrk -t 12 -c 400 -d 30s --latency http://10.10.2.20/ 2>&1 | tee benchmark_fast.txt

echo ""
echo "==================================="
echo "📊 RESULTS"
echo "==================================="

grep "Requests/sec:" benchmark_fast.txt
grep "Latency" benchmark_fast.txt | head -n 5

echo ""
echo "==================================="
echo "🛑 STOPPING FILTER"
echo "==================================="

sudo pkill -SIGINT tiger-fox
sleep 2

echo "✅ DONE"
