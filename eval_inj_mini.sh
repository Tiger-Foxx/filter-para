#!/bin/bash

################################################################################
# Script d'évaluation MANUEL côté INJECTEUR
# Usage: ./eval_inj_mini.sh <mode> [workers]
# Exemples:
#   ./eval_inj_mini.sh sequential
#   ./eval_inj_mini.sh parallel 4
################################################################################

MODE="$1"
WORKERS="$2"
SERVER_IP="10.10.2.20"
PING_DURATION=20
WRK_DURATION=50
WRK_THREADS=4
WRK_CONN=500

if [ -z "$MODE" ]; then
    echo "Usage: $0 <sequential|parallel> [workers]"
    echo "Exemples:"
    echo "  $0 sequential"
    echo "  $0 parallel 4"
    exit 1
fi

if [ "$MODE" == "parallel" ] && [ -z "$WORKERS" ]; then
    echo "❌ ERREUR: Vous devez spécifier le nombre de workers pour le mode parallel"
    echo "Exemple: $0 parallel 4"
    exit 1
fi

if ! command -v wrk &> /dev/null; then
    echo "❌ ERREUR: wrk n'est pas installé"
    exit 1
fi

# Configuration du dossier
if [ "$MODE" == "parallel" ]; then
    FOLDER="inj_mode_parallel_${WORKERS}_workers"
    TEST_NAME="Mode PARALLEL avec $WORKERS workers"
else
    FOLDER="inj_mode_sequential"
    TEST_NAME="Mode SEQUENTIAL"
fi

mkdir -p "$FOLDER"
cd "$FOLDER"

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  ÉVALUATION MANUELLE - INJECTEUR                                       ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Test: $TEST_NAME"
echo "📁 Dossier: $FOLDER"
echo "🎯 Cible: $SERVER_IP"
echo ""

# Vérification connectivité
echo "[$(date +%H:%M:%S)] 🔍 Vérification de la connectivité..."
if ! ping -c 3 -W 5 $SERVER_IP &> /dev/null; then
    echo "❌ ERREUR: Le serveur $SERVER_IP n'est pas accessible!"
    exit 1
fi
echo "[$(date +%H:%M:%S)] ✅ Serveur accessible"

# Test PING
echo "[$(date +%H:%M:%S)] 📡 Test PING (${PING_DURATION}s)..."
ping $SERVER_IP -i 0.2 -w $PING_DURATION > ping_results.txt 2>&1

# Extraction stats ping
if grep -q "rtt min/avg/max" ping_results.txt; then
    PING_STATS=$(grep "rtt min/avg/max" ping_results.txt | awk -F'=' '{print $2}')
    PING_MIN=$(echo $PING_STATS | awk -F'/' '{print $1}')
    PING_AVG=$(echo $PING_STATS | awk -F'/' '{print $2}')
    PING_MAX=$(echo $PING_STATS | awk -F'/' '{print $3}' | awk '{print $1}')
    PING_LOSS=$(grep "packet loss" ping_results.txt | awk -F',' '{print $3}' | awk '{print $1}')
    
    echo "   ✅ Ping terminé - Avg: ${PING_AVG}ms, Loss: ${PING_LOSS}"
else
    PING_MIN="N/A"
    PING_AVG="N/A"
    PING_MAX="N/A"
    PING_LOSS="N/A"
fi

grep "time=" ping_results.txt | awk -F'time=' '{print $2}' | awk '{print $1}' > ping_latencies.csv

# Test WRK
echo "[$(date +%H:%M:%S)] 🔥 Test WRK (${WRK_DURATION}s, -t$WRK_THREADS -c$WRK_CONN)..."
sudo wrk -t$WRK_THREADS -c$WRK_CONN -d${WRK_DURATION}s --latency http://$SERVER_IP > wrk_results.txt 2>&1

# Extraction stats wrk
if grep -q "Requests/sec" wrk_results.txt; then
    WRK_REQ_SEC=$(grep "Requests/sec:" wrk_results.txt | awk '{print $2}')
    WRK_TRANSFER=$(grep "Transfer/sec:" wrk_results.txt | awk '{print $2}')
    WRK_LAT_AVG=$(grep "Latency" wrk_results.txt | head -1 | awk '{print $2}')
    WRK_LAT_MAX=$(grep "Latency" wrk_results.txt | head -1 | awk '{print $4}')
    
    echo "   ✅ Wrk terminé - Req/s: ${WRK_REQ_SEC}, Latency: ${WRK_LAT_AVG}"
else
    WRK_REQ_SEC="N/A"
    WRK_TRANSFER="N/A"
    WRK_LAT_AVG="N/A"
    WRK_LAT_MAX="N/A"
fi

awk '/Latency Distribution/,/Requests\/sec/ {print}' wrk_results.txt | grep "%" | awk '{print $1";"$2}' > wrk_latency_distribution.csv

# Résumé
cat > summary.csv << EOF
Metric;Value;Unit
Ping_Min;$PING_MIN;ms
Ping_Avg;$PING_AVG;ms
Ping_Max;$PING_MAX;ms
Ping_Loss;$PING_LOSS;%
Wrk_Requests_Per_Sec;$WRK_REQ_SEC;req/s
Wrk_Transfer_Per_Sec;$WRK_TRANSFER;MB/s
Wrk_Latency_Avg;$WRK_LAT_AVG;ms
Wrk_Latency_Max;$WRK_LAT_MAX;ms
EOF

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  ✅ TEST TERMINÉ!                                                      ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📁 Résultats dans: $(pwd)"
echo ""
echo "📊 Fichiers générés:"
ls -lh | tail -n +2 | awk '{printf "   - %-35s (%s)\n", $9, $5}'
echo ""
echo "📊 Résumé des performances:"
echo "   PING  → Min: ${PING_MIN}ms | Avg: ${PING_AVG}ms | Max: ${PING_MAX}ms | Loss: ${PING_LOSS}"
echo "   WRK   → Req/s: ${WRK_REQ_SEC} | Latency: ${WRK_LAT_AVG} (avg) / ${WRK_LAT_MAX} (max)"
echo ""
