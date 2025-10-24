#!/bin/bash

################################################################################
# Script d'évaluation automatique côté INJECTEUR
# Teste automatiquement : sequential, parallel (2,3,4,5,6,7,8,16 workers)
# + test bonus avec charge doublée (sequential et parallel 4 workers)
# Mesure : Ping latency, Wrk throughput & latency
################################################################################

set -e  # Arrêt en cas d'erreur

# Configuration
SERVER_IP="10.10.2.20"
PING_DURATION=20
WRK_DURATION=50
STARTUP_MARGIN=3
SHUTDOWN_MARGIN=2

# Configuration standard
WRK_THREADS_NORMAL=4
WRK_CONN_NORMAL=500

# Configuration bonus (charge doublée)
WRK_THREADS_BONUS=8
WRK_CONN_BONUS=1000

RESULTS_DIR="injector_results_$(date +%Y%m%d_%H%M%S)"

# Vérification des prérequis
if ! command -v wrk &> /dev/null; then
    echo "❌ ERREUR: wrk n'est pas installé"
    echo "   Pour l'installer: sudo apt-get install wrk"
    exit 1
fi

if ! ping -c 1 $SERVER_IP &> /dev/null; then
    echo "❌ ERREUR: Impossible de pinguer le serveur $SERVER_IP"
    echo "   Vérifiez que le serveur est accessible"
    exit 1
fi

# Création du dossier de résultats
mkdir -p "$RESULTS_DIR"
cd "$RESULTS_DIR"

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  ÉVALUATION AUTOMATIQUE - CÔTÉ INJECTEUR                               ║"
echo "║  Résultats dans: $RESULTS_DIR"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "⚠️  IMPORTANT: Assurez-vous que le filtreur a démarré son script eval.sh!"
echo ""

# Fonction pour exécuter un test
run_test() {
    local MODE="$1"
    local WORKERS="$2"
    local IS_BONUS="$3"
    
    # Configuration du wrk selon le type de test
    if [ "$IS_BONUS" == "true" ]; then
        WRK_THREADS=$WRK_THREADS_BONUS
        WRK_CONN=$WRK_CONN_BONUS
    else
        WRK_THREADS=$WRK_THREADS_NORMAL
        WRK_CONN=$WRK_CONN_NORMAL
    fi
    
    if [ "$MODE" == "sequential" ]; then
        if [ "$IS_BONUS" == "true" ]; then
            FOLDER="test_bonus_sequential"
            TEST_NAME="SEQUENTIAL (BONUS - Charge doublée)"
        else
            FOLDER="test_01_sequential"
            TEST_NAME="SEQUENTIAL"
        fi
    else
        if [ "$IS_BONUS" == "true" ]; then
            FOLDER="test_bonus_parallel_${WORKERS}_workers"
            TEST_NAME="PARALLEL ${WORKERS} WORKERS (BONUS - Charge doublée)"
        else
            FOLDER=$(printf "test_%02d_parallel_%02d_workers" $((WORKERS + 1)) $WORKERS)
            TEST_NAME="PARALLEL ${WORKERS} WORKERS"
        fi
    fi
    
    mkdir -p "$FOLDER"
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🚀 Démarrage du test: $TEST_NAME"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "   Dossier: $FOLDER"
    echo "   Wrk config: -t$WRK_THREADS -c$WRK_CONN"
    echo ""
    
    # Attente que le filtreur soit prêt
    echo "[$(date +%H:%M:%S)] ⏳ Attente du démarrage du filtreur (${STARTUP_MARGIN}s)..."
    sleep $STARTUP_MARGIN
    
    # Test de connectivité
    echo "[$(date +%H:%M:%S)] 🔍 Vérification de la connectivité..."
    if ! ping -c 2 $SERVER_IP &> /dev/null; then
        echo "❌ ERREUR: Le serveur $SERVER_IP n'est pas accessible!"
        echo "   Le filtreur est-il bien démarré?"
        return 1
    fi
    echo "[$(date +%H:%M:%S)] ✅ Serveur accessible"
    
    # Phase 1: Test PING
    echo "[$(date +%H:%M:%S)] 📡 Démarrage du test PING (${PING_DURATION}s)..."
    ping $SERVER_IP -i 0.2 -w $PING_DURATION > "$FOLDER/ping_results.txt" 2>&1
    
    # Extraction des statistiques de ping
    if grep -q "rtt min/avg/max" "$FOLDER/ping_results.txt"; then
        PING_STATS=$(grep "rtt min/avg/max" "$FOLDER/ping_results.txt" | awk -F'=' '{print $2}')
        PING_MIN=$(echo $PING_STATS | awk -F'/' '{print $1}')
        PING_AVG=$(echo $PING_STATS | awk -F'/' '{print $2}')
        PING_MAX=$(echo $PING_STATS | awk -F'/' '{print $3}' | awk '{print $1}')
        PING_LOSS=$(grep "packet loss" "$FOLDER/ping_results.txt" | awk -F',' '{print $3}' | awk '{print $1}')
        
        echo "   ✅ Ping terminé - Avg: ${PING_AVG}ms, Loss: ${PING_LOSS}"
    else
        echo "   ⚠️  Ping terminé (statistiques non disponibles)"
        PING_MIN="N/A"
        PING_AVG="N/A"
        PING_MAX="N/A"
        PING_LOSS="N/A"
    fi
    
    # Formatage des latences ping en CSV
    grep "time=" "$FOLDER/ping_results.txt" | awk -F'time=' '{print $2}' | awk '{print $1}' > "$FOLDER/ping_latencies.csv"
    
    # Phase 2: Test WRK
    echo "[$(date +%H:%M:%S)] 🔥 Démarrage du test WRK (${WRK_DURATION}s, threads:$WRK_THREADS, conn:$WRK_CONN)..."
    sudo wrk -t$WRK_THREADS -c$WRK_CONN -d${WRK_DURATION}s --latency http://$SERVER_IP > "$FOLDER/wrk_results.txt" 2>&1
    
    # Extraction des statistiques de wrk
    if grep -q "Requests/sec" "$FOLDER/wrk_results.txt"; then
        WRK_REQ_SEC=$(grep "Requests/sec:" "$FOLDER/wrk_results.txt" | awk '{print $2}')
        WRK_TRANSFER=$(grep "Transfer/sec:" "$FOLDER/wrk_results.txt" | awk '{print $2}')
        WRK_LAT_AVG=$(grep "Latency" "$FOLDER/wrk_results.txt" | head -1 | awk '{print $2}')
        WRK_LAT_MAX=$(grep "Latency" "$FOLDER/wrk_results.txt" | head -1 | awk '{print $4}')
        
        echo "   ✅ Wrk terminé - Req/s: ${WRK_REQ_SEC}, Latency avg: ${WRK_LAT_AVG}"
    else
        echo "   ⚠️  Wrk terminé (statistiques non disponibles)"
        WRK_REQ_SEC="N/A"
        WRK_TRANSFER="N/A"
        WRK_LAT_AVG="N/A"
        WRK_LAT_MAX="N/A"
    fi
    
    # Extraction des latences wrk détaillées
    awk '/Latency Distribution/,/Requests\/sec/ {print}' "$FOLDER/wrk_results.txt" | grep "%" | awk '{print $1";"$2}' > "$FOLDER/wrk_latency_distribution.csv"
    
    # Création d'un fichier de métadonnées
    cat > "$FOLDER/test_metadata.txt" << EOF
Test: $TEST_NAME
Date: $(date '+%Y-%m-%d %H:%M:%S')
Mode: $MODE
Workers: ${WORKERS:-N/A}
Server IP: $SERVER_IP
Ping Duration: ${PING_DURATION}s
Wrk Duration: ${WRK_DURATION}s
Wrk Threads: $WRK_THREADS
Wrk Connections: $WRK_CONN
Bonus Test: ${IS_BONUS:-false}
EOF
    
    # Création d'un fichier de résumé
    cat > "$FOLDER/summary.csv" << EOF
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
    
    # Listing des fichiers générés
    echo ""
    echo "✅ Test terminé avec succès!"
    echo "   Fichiers générés dans $FOLDER:"
    ls -lh "$FOLDER" | tail -n +2 | awk '{printf "     - %-35s (%s)\n", $9, $5}'
    
    echo ""
    echo "   📊 Résumé des performances:"
    echo "      PING  → Min: ${PING_MIN}ms | Avg: ${PING_AVG}ms | Max: ${PING_MAX}ms | Loss: ${PING_LOSS}"
    echo "      WRK   → Req/s: ${WRK_REQ_SEC} | Latency: ${WRK_LAT_AVG} (avg) / ${WRK_LAT_MAX} (max)"
    
    sleep 2  # Pause entre les tests pour laisser le filtreur se préparer
}

# ============================================================================
# TESTS STANDARDS
# ============================================================================

echo ""
echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃  PHASE 1: TESTS STANDARDS (Charge normale: -t4 -c500)              ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"

# Test séquentiel
run_test "sequential" "" "false"

# Tests parallèles avec différents nombres de workers
for WORKERS in 2 3 4 5 6 7 8 16; do
    run_test "parallel" "$WORKERS" "false"
done

# ============================================================================
# TESTS BONUS (Charge doublée)
# ============================================================================

echo ""
echo ""
echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃  PHASE 2: TESTS BONUS (Charge doublée: -t8 -c1000)                 ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"

run_test "sequential" "" "true"
run_test "parallel" "4" "true"

# ============================================================================
# RÉSUMÉ FINAL
# ============================================================================

echo ""
echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  🎉 TOUS LES TESTS TERMINÉS AVEC SUCCÈS!                              ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📁 Résultats complets dans: $(pwd)"
echo ""
echo "📊 Structure des résultats:"
tree -L 1 . 2>/dev/null || ls -1 | sed 's/^/   /'
echo ""
echo "💡 Prochaines étapes:"
echo "   1. Récupérer ce dossier sur votre machine locale"
echo "   2. Récupérer également le dossier du filtreur"
echo "   3. Exécuter: python3 analyze_results.py"
echo ""

# Création d'un fichier de résumé global
echo "Génération du résumé global..."
{
    echo "Test;Ping_Avg_ms;Ping_Loss;Wrk_Req_Sec;Wrk_Lat_Avg"
    for dir in test_*/; do
        if [ -f "$dir/summary.csv" ]; then
            TEST_NAME=$(basename "$dir")
            PING_AVG=$(grep "Ping_Avg" "$dir/summary.csv" | awk -F';' '{print $2}')
            PING_LOSS=$(grep "Ping_Loss" "$dir/summary.csv" | awk -F';' '{print $2}')
            WRK_REQ=$(grep "Wrk_Requests_Per_Sec" "$dir/summary.csv" | awk -F';' '{print $2}')
            WRK_LAT=$(grep "Wrk_Latency_Avg" "$dir/summary.csv" | awk -F';' '{print $2}')
            echo "$TEST_NAME;$PING_AVG;$PING_LOSS;$WRK_REQ;$WRK_LAT"
        fi
    done
} > global_summary.csv

echo ""
echo "📄 Résumé global créé: global_summary.csv"
echo ""
