#!/bin/bash

# ==============================================================
# PERFORMANCE TEST SCRIPT FOR TIGER-FOX
# ==============================================================
# Usage: ./test_performance.sh
# 
# This script tests the filter performance with various workloads
# and produces a comprehensive performance report.
# ==============================================================

echo "🚀 Tiger-Fox Performance Testing Suite"
echo "========================================================"
echo ""

# Configuration
SERVER_IP="10.10.2.20"
TEST_DURATION=30
CONNECTIONS=500
THREADS=4

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Results storage
RESULTS_FILE="performance_results_$(date +%Y%m%d_%H%M%S).txt"

echo "📊 Test Configuration:" | tee -a "$RESULTS_FILE"
echo "   Target: $SERVER_IP" | tee -a "$RESULTS_FILE"
echo "   Duration: ${TEST_DURATION}s per test" | tee -a "$RESULTS_FILE"
echo "   Connections: $CONNECTIONS" | tee -a "$RESULTS_FILE"
echo "   Threads: $THREADS" | tee -a "$RESULTS_FILE"
echo "   Results: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ==============================================================
# TEST 1: Baseline - Simple GET requests
# ==============================================================
echo -e "${GREEN}TEST 1: Baseline Performance (GET /)${NC}" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
wrk -t${THREADS} -c${CONNECTIONS} -d${TEST_DURATION}s "http://${SERVER_IP}/" 2>&1 | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
sleep 2

# ==============================================================
# TEST 2: Light load
# ==============================================================
echo -e "${GREEN}TEST 2: Light Load (100 connections)${NC}" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
wrk -t${THREADS} -c100 -d${TEST_DURATION}s "http://${SERVER_IP}/" 2>&1 | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
sleep 2

# ==============================================================
# TEST 3: Heavy load
# ==============================================================
echo -e "${GREEN}TEST 3: Heavy Load (1000 connections)${NC}" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
wrk -t${THREADS} -c1000 -d${TEST_DURATION}s "http://${SERVER_IP}/" 2>&1 | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
sleep 2

# ==============================================================
# TEST 4: Sustained load (longer duration)
# ==============================================================
echo -e "${GREEN}TEST 4: Sustained Load (2 minutes)${NC}" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
wrk -t${THREADS} -c${CONNECTIONS} -d120s "http://${SERVER_IP}/" 2>&1 | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"
sleep 2

# ==============================================================
# TEST 5: Latency focused (low connections)
# ==============================================================
echo -e "${GREEN}TEST 5: Latency Test (10 connections)${NC}" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
wrk -t1 -c10 -d${TEST_DURATION}s "http://${SERVER_IP}/" 2>&1 | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ==============================================================
# SUMMARY
# ==============================================================
echo "========================================================" | tee -a "$RESULTS_FILE"
echo -e "${YELLOW}📊 Performance Test Summary${NC}" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Extract key metrics
echo "Extracting key metrics..." | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

grep "Requests/sec:" "$RESULTS_FILE" | nl | tee -a "${RESULTS_FILE}.summary"
echo "" | tee -a "$RESULTS_FILE"
grep "Latency" "$RESULTS_FILE" | grep "Avg" | nl | tee -a "${RESULTS_FILE}.summary"
echo "" | tee -a "$RESULTS_FILE"
grep "timeout" "$RESULTS_FILE" | nl | tee -a "${RESULTS_FILE}.summary"

echo "" | tee -a "$RESULTS_FILE"
echo -e "${GREEN}✅ Tests completed!${NC}" | tee -a "$RESULTS_FILE"
echo "Full results saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "Summary saved to: ${RESULTS_FILE}.summary" | tee -a "$RESULTS_FILE"
