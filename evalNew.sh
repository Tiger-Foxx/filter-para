#!/bin/bash

################################################################################
# Script d'évaluation automatique côté FILTREUR
# Teste automatiquement : sequential, parallel (2,3,4,5,6,7,8,16 workers)
# + test bonus avec charge doublée (sequential et parallel 4 workers)
# Mesure : CPU, Énergie (turbostat + powerstat)
################################################################################

# Configuration
RULES="/users/The_Fox/filter-para/rules/example_rules_backup2.json"
QUEUE_NUM=0
PING_DURATION=20
WRK_DURATION=50
STARTUP_MARGIN=3
SHUTDOWN_MARGIN=2
TEST_DURATION=$((PING_DURATION + WRK_DURATION + STARTUP_MARGIN + SHUTDOWN_MARGIN))  # 75 secondes

RESULTS_DIR="filter_results_$(date +%Y%m%d_%H%M%S)"
BUILD_DIR="$(pwd)/build"
TIGER_FOX="$BUILD_DIR/tiger-fox"

# Vérification des prérequis
if [ ! -f "$TIGER_FOX" ]; then
    echo "ERREUR: tiger-fox non trouvé dans $BUILD_DIR"
    echo "   Compilez d'abord avec: ./build.sh"
    exit 1
fi

# Vérification turbostat
if ! command -v turbostat &> /dev/null; then
    echo "WARNING: turbostat non installé. Mesure énergétique CPU désactivée."
    echo "   Pour l'installer: sudo apt-get install linux-tools-common linux-tools-generic"
    USE_TURBOSTAT=false
else
    USE_TURBOSTAT=true
fi

# Vérification powerstat
if ! command -v powerstat &> /dev/null; then
    echo "WARNING: powerstat non installé. Mesure énergétique machine désactivée."
    echo "   Pour l'installer: sudo apt-get install powerstat"
    USE_POWERSTAT=false
else
    USE_POWERSTAT=true
fi

# Création du dossier de résultats
mkdir -p "$RESULTS_DIR"
cd "$RESULTS_DIR"

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  ÉVALUATION AUTOMATIQUE - CÔTÉ FILTREUR                                ║"
echo "║  Résultats dans: $(pwd)"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""

# Fonction pour exécuter un test
run_test() {
    local MODE="$1"
    local WORKERS="$2"
    local IS_BONUS="$3"
    
    if [ "$MODE" == "sequential" ]; then
        if [ "$IS_BONUS" == "true" ]; then
            FOLDER="test_bonus_sequential"
            TEST_NAME="SEQUENTIAL (BONUS - Charge doublée)"
        else
            FOLDER="test_01_sequential"
            TEST_NAME="SEQUENTIAL"
        fi
        CMD="sudo $TIGER_FOX --mode sequential --rules $RULES --queue-num $QUEUE_NUM"
    else
        if [ "$IS_BONUS" == "true" ]; then
            FOLDER="test_bonus_parallel_${WORKERS}_workers"
            TEST_NAME="PARALLEL ${WORKERS} WORKERS (BONUS - Charge doublée)"
        else
            FOLDER=$(printf "test_%02d_parallel_%02d_workers" $((WORKERS + 1)) $WORKERS)
            TEST_NAME="PARALLEL ${WORKERS} WORKERS"
        fi
        CMD="sudo $TIGER_FOX --mode parallel --rules $RULES --workers $WORKERS --queue-num $QUEUE_NUM"
    fi
    
    mkdir -p "$FOLDER"
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Démarrage du test: $TEST_NAME"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "   Dossier: $FOLDER"
    echo "   Durée: ${TEST_DURATION}s"
    echo ""
    
    # Nettoyage
    sudo pkill -9 tiger-fox 2>/dev/null || true
    sleep 1
    
    # Démarrage moniteurs CPU
    echo "[$(date +%H:%M:%S)] Démarrage des moniteurs CPU..."
    mpstat -P ALL 1 $TEST_DURATION | awk 'BEGIN{FS=" ";OFS=";"} /^[0-9]+:[0-9]+:[0-9]+/ && !/Linux/ && !/^$/ {gsub(/^ +| +$/,"",$3); print $3,$4,$5,$6,$7,$8,$9,$10,$11,$12}' > "$FOLDER/cpu_all.csv" &
    MPSTAT_PID=$!
    
    # Lancement Tiger-Fox
    echo "[$(date +%H:%M:%S)] Lancement de Tiger-Fox..."
    $CMD > "$FOLDER/tiger_fox_output.log" 2>&1 &
    APP_PID=$!
    
    sleep $STARTUP_MARGIN
    
    if ! ps -p $APP_PID > /dev/null; then
        echo "ERREUR: Tiger-Fox s'est arrêté prématurément!"
        wait $MPSTAT_PID 2>/dev/null || true
        return 1
    fi
    
    echo "[$(date +%H:%M:%S)] Tiger-Fox opérationnel (PID: $APP_PID)"
    
    # Moniteurs CPU spécifiques
    pidstat -p $APP_PID 1 $TEST_DURATION | awk 'BEGIN{FS=" ";OFS=";"} /^[0-9]+:[0-9]+:[0-9]+/ && !/Linux/ && !/Average/ {print $1,$4,$5,$6,$7,$8}' > "$FOLDER/cpu_app.csv" &
    PIDSTAT_PID=$!
    
    top -b -d 1 -n $TEST_DURATION | grep --line-buffered "Cpu(s)" | awk '{print $2}' > "$FOLDER/cpu_log_interval.csv" &
    TOP_PID=$!
    
    # Énergie CPU (turbostat)
    if [ "$USE_TURBOSTAT" == "true" ]; then
        echo "[$(date +%H:%M:%S)] Mesure énergétique CPU (turbostat)..."
        sudo turbostat --quiet --show PkgWatt,CorWatt,RAMWatt --interval 1 sleep $TEST_DURATION > "$FOLDER/energy_cpu_turbostat.log" 2>&1 &
        TURBOSTAT_PID=$!
    else
        TURBOSTAT_PID=""
    fi
    
    # Énergie machine (powerstat) - FORME FIABLE
    if [ "$USE_POWERSTAT" == "true" ]; then
        echo "[$(date +%H:%M:%S)] Mesure énergétique MACHINE (powerstat)..."
        sudo powerstat -r -d 0 1 $TEST_DURATION > "$FOLDER/energy_machine_powerstat.log" 2>&1 &
        POWERSTAT_PID=$!
    else
        POWERSTAT_PID=""
    fi
    
    echo "[$(date +%H:%M:%S)] Collecte en cours... (injecteur doit lancer les tests)"
    
    sleep $TEST_DURATION
    
    # Arrêt propre
    echo "[$(date +%H:%M:%S)] Arrêt de Tiger-Fox..."
    sudo kill -SIGINT $APP_PID 2>/dev/null || true
    sleep $SHUTDOWN_MARGIN
    if ps -p $APP_PID > /dev/null 2>&1; then
        sudo kill -SIGKILL $APP_PID 2>/dev/null || true
    fi
    
    # Attente moniteurs
    wait $MPSTAT_PID 2>/dev/null || true
    wait $PIDSTAT_PID 2>/dev/null || true
    wait $TOP_PID 2>/dev/null || true
    [ -n "$TURBOSTAT_PID" ] && wait $TURBOSTAT_PID 2>/dev/null || true
    [ -n "$POWERSTAT_PID" ] && wait $POWERSTAT_PID 2>/dev/null || true
    
    # === TURBOSTAT PARSING (4 packages) ===
    if [ "$USE_TURBOSTAT" == "true" ] && [ -f "$FOLDER/energy_cpu_turbostat.log" ]; then
        awk '
        NR==1 {
            for(i=1; i<=NF; i++) {
                if($i == "PkgWatt") pkg_cols[pkg_count++] = i;
                if($i == "CorWatt") cor_col = i;
                if($i == "RAMWatt") ram_cols[ram_count++] = i;
            }
            next;
        }
        /^[0-9]/ {
            pkg_sum = 0; ram_sum = 0; cor = 0;
            for(i=0; i<pkg_count; i++) {
                col = pkg_cols[i];
                if(col <= NF) pkg_sum += $(col);
            }
            for(i=0; i<ram_count; i++) {
                col = ram_cols[i];
                if(col <= NF) ram_sum += $(col);
            }
            if(cor_col <= NF) cor = $(cor_col);
            print pkg_sum ";" cor ";" ram_sum;
        }
        ' "$FOLDER/energy_cpu_turbostat.log" > "$FOLDER/energy_cpu_watts.csv"
        
        AVG_PKG=$(awk -F';' '{sum+=$1; c++} END {printf "%.2f", sum/c}' "$FOLDER/energy_cpu_watts.csv")
        AVG_CORE=$(awk -F';' '{sum+=$2; c++} END {printf "%.2f", sum/c}' "$FOLDER/energy_cpu_watts.csv")
        AVG_RAM=$(awk -F';' '{sum+=$3; c++} END {printf "%.2f", sum/c}' "$FOLDER/energy_cpu_watts.csv")
        
        echo "Package_Watt;Core_Watt;RAM_Watt" > "$FOLDER/energy_cpu_summary.csv"
        echo "$AVG_PKG;$AVG_CORE;$AVG_RAM" >> "$FOLDER/energy_cpu_summary.csv"
    else
        AVG_PKG="N/A"; AVG_CORE="N/A"; AVG_RAM="N/A"
    fi
    
    # === POWERSTAT PARSING (FIABLE) ===
    if [ "$USE_POWERSTAT" == "true" ] && [ -f "$FOLDER/energy_machine_powerstat.log" ]; then
        # Extraire toutes les valeurs Watts
        awk '/[0-9]+\.[0-9]+$/ && $NF ~ /^[0-9]+\.[0-9]+$/ {print $NF}' "$FOLDER/energy_machine_powerstat.log" > "$FOLDER/energy_machine_watts.csv"
        
        if [ -s "$FOLDER/energy_machine_watts.csv" ]; then
            AVG_MACHINE=$(awk '{sum+=$1; c++} END {printf "%.2f", sum/c}' "$FOLDER/energy_machine_watts.csv")
        else
            AVG_MACHINE="N/A"
        fi
        
        echo "Machine_Total_Watt" > "$FOLDER/energy_machine_summary.csv"
        echo "$AVG_MACHINE" >> "$FOLDER/energy_machine_summary.csv"
    else
        AVG_MACHINE="N/A"
    fi
    
    # Métadonnées
    cat > "$FOLDER/test_metadata.txt" << EOF
Test: $TEST_NAME
Date: $(date '+%Y-%m-%d %H:%M:%S')
Mode: $MODE
Workers: ${WORKERS:-N/A}
Duration: ${TEST_DURATION}s
Tiger-Fox PID: $APP_PID
Rules File: $RULES
Queue Number: $QUEUE_NUM
Bonus Test: ${IS_BONUS:-false}
EOF
    
    # Résumé
    echo ""
    echo "Test terminé: $FOLDER"
    if [ "$USE_TURBOSTAT" == "true" ] && [ "$AVG_PKG" != "N/A" ]; then
        echo "   CPU: $AVG_PKG W (pkg), $AVG_CORE W (cores), $AVG_RAM W (RAM)"
    fi
    if [ "$USE_POWERSTAT" == "true" ] && [ "$AVG_MACHINE" != "N/A" ]; then
        echo "   Machine: $AVG_MACHINE W"
    fi
    
    echo "Pause 5s..."
    sleep 5
}

# === LANCEMENT DES TESTS ===
echo "PHASE 1: TESTS STANDARDS"
run_test "sequential" "" "false"
for w in 2 3 4 5 6 7 8 16; do run_test "parallel" "$w" "false"; done

echo "PHASE 2: TESTS BONUS"
echo "IMPORTANT: Injecteur doit utiliser wrk -t8 -c1000"
run_test "sequential" "" "true"
run_test "parallel" "4" "true"

# === FIN ===
echo "TOUS LES TESTS TERMINÉS!"
echo "Résultats dans: $(pwd)"
tree -L 1 . 2>/dev/null || ls -1
echo "Récupérez ce dossier + celui de l'injecteur → python3 analyze_results.py"