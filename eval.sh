#!/bin/bash

################################################################################
# Script d'évaluation automatique côté FILTREUR
# Teste automatiquement : sequential, parallel (2,3,4,5,6,7,8,16 workers)
# + test bonus avec charge doublée (sequential et parallel 4 workers)
# Mesure : CPU, Énergie (turbostat)
################################################################################

set -e  # Arrêt en cas d'erreur

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
    echo "❌ ERREUR: tiger-fox non trouvé dans $BUILD_DIR"
    echo "   Compilez d'abord avec: ./build.sh"
    exit 1
fi

# Vérification turbostat (mesure CPU détaillée)
if ! command -v turbostat &> /dev/null; then
    echo "⚠️  WARNING: turbostat non installé. Mesure énergétique CPU désactivée."
    echo "   Pour l'installer: sudo apt-get install linux-tools-common linux-tools-generic"
    USE_TURBOSTAT=false
else
    USE_TURBOSTAT=true
fi

# Vérification powerstat (mesure machine complète)
if ! command -v powerstat &> /dev/null; then
    echo "⚠️  WARNING: powerstat non installé. Mesure énergétique machine désactivée."
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
echo "║  Résultats dans: $RESULTS_DIR"
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
    echo "🚀 Démarrage du test: $TEST_NAME"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "   Dossier: $FOLDER"
    echo "   Durée: ${TEST_DURATION}s (Ping: ${PING_DURATION}s + Wrk: ${WRK_DURATION}s + Marges: $((STARTUP_MARGIN + SHUTDOWN_MARGIN))s)"
    echo ""
    
    # Nettoyage des processus précédents (au cas où)
    sudo pkill -9 tiger-fox 2>/dev/null || true
    sleep 1
    
    # Démarrage des moniteurs CPU
    echo "[$(date +%H:%M:%S)] 📊 Démarrage des moniteurs CPU..."
    mpstat -P ALL 1 $TEST_DURATION | awk 'BEGIN{FS=" ";OFS=";"} /^[0-9]+:[0-9]+:[0-9]+/ && !/Linux/ && !/^$/ {gsub(/^ +| +$/,"",$3); print $3,$4,$5,$6,$7,$8,$9,$10,$11,$12}' > "$FOLDER/cpu_all.csv" &
    MPSTAT_PID=$!
    
    # Démarrage du programme Tiger-Fox
    echo "[$(date +%H:%M:%S)] 🦊 Lancement de Tiger-Fox..."
    $CMD > "$FOLDER/tiger_fox_output.log" 2>&1 &
    APP_PID=$!
    
    # Attente que le programme soit prêt
    sleep $STARTUP_MARGIN
    
    # Vérification que le programme tourne toujours
    if ! ps -p $APP_PID > /dev/null; then
        echo "❌ ERREUR: Tiger-Fox s'est arrêté prématurément!"
        echo "   Voir les logs dans: $FOLDER/tiger_fox_output.log"
        wait $MPSTAT_PID 2>/dev/null || true
        return 1
    fi
    
    echo "[$(date +%H:%M:%S)] ✅ Tiger-Fox opérationnel (PID: $APP_PID)"
    
    # Moniteur CPU du programme spécifique
    pidstat -p $APP_PID 1 $TEST_DURATION | awk 'BEGIN{FS=" ";OFS=";"} /^[0-9]+:[0-9]+:[0-9]+/ && !/Linux/ && !/Average/ {print $1,$4,$5,$6,$7,$8}' > "$FOLDER/cpu_app.csv" &
    PIDSTAT_PID=$!
    
    # Moniteur CPU à intervalles (pour analyse temporelle) - COMME AVANT
    top -b -d 1 -n $TEST_DURATION | grep --line-buffered "Cpu(s)" | awk '{print $2}' > "$FOLDER/cpu_log_interval.csv" &
    TOP_PID=$!
    
    # Moniteur énergétique CPU avec turbostat (si disponible)
    if [ "$USE_TURBOSTAT" == "true" ]; then
        echo "[$(date +%H:%M:%S)] ⚡ Démarrage de la mesure énergétique CPU (turbostat)..."
        sudo turbostat --quiet --show PkgWatt,CorWatt,RAMWatt --interval 1 sleep $TEST_DURATION > "$FOLDER/energy_cpu_turbostat.log" 2>&1 &
        TURBOSTAT_PID=$!
    else
        TURBOSTAT_PID=""
    fi
    
    # Moniteur énergétique MACHINE COMPLÈTE avec powerstat (si disponible)
    if [ "$USE_POWERSTAT" == "true" ]; then
        echo "[$(date +%H:%M:%S)] 🔋 Démarrage de la mesure énergétique MACHINE (powerstat)..."
        # powerstat échantillonne toutes les secondes pendant TEST_DURATION secondes
        sudo powerstat -R -d 0 1 $TEST_DURATION > "$FOLDER/energy_machine_powerstat.log" 2>&1 &
        POWERSTAT_PID=$!
    else
        POWERSTAT_PID=""
    fi
    
    echo "[$(date +%H:%M:%S)] ⏳ Collecte des métriques en cours..."
    echo "                      (L'injecteur doit maintenant lancer ses tests)"
    
    # Attente de la fin du test
    sleep $TEST_DURATION
    
    # Arrêt propre de Tiger-Fox
    echo "[$(date +%H:%M:%S)] 🛑 Arrêt de Tiger-Fox..."
    sudo kill -SIGINT $APP_PID 2>/dev/null || true
    sleep $SHUTDOWN_MARGIN
    
    # Force l'arrêt si encore actif
    if ps -p $APP_PID > /dev/null 2>&1; then
        echo "[$(date +%H:%M:%S)] ⚠️  Arrêt forcé nécessaire..."
        sudo kill -SIGKILL $APP_PID 2>/dev/null || true
    fi
    
    # Attente de la fin des moniteurs
    wait $MPSTAT_PID 2>/dev/null || true
    wait $PIDSTAT_PID 2>/dev/null || true
    wait $TOP_PID 2>/dev/null || true
    [ -n "$TURBOSTAT_PID" ] && wait $TURBOSTAT_PID 2>/dev/null || true
    [ -n "$POWERSTAT_PID" ] && wait $POWERSTAT_PID 2>/dev/null || true
    
    # Formatage des données énergétiques CPU (turbostat)
    if [ "$USE_TURBOSTAT" == "true" ] && [ -f "$FOLDER/energy_cpu_turbostat.log" ]; then
        echo "[$(date +%H:%M:%S)] 📊 Formatage des données énergétiques CPU..."
        
        # Parser turbostat : trouver les colonnes dynamiquement
        awk '
        BEGIN { pkg_col=0; cor_col=0; ram_col=0; }
        NR==1 {
            for(i=1; i<=NF; i++) {
                if($i == "PkgWatt") pkg_col=i;
                if($i == "CorWatt") cor_col=i;
                if($i == "RAMWatt") ram_col=i;
            }
            next;
        }
        pkg_col && /^[0-9]/ {
            pkg = (pkg_col && pkg_col<=NF) ? $pkg_col : "0";
            cor = (cor_col && cor_col<=NF) ? $cor_col : "0";
            ram = (ram_col && ram_col<=NF) ? $ram_col : "0";
            print pkg";"cor";"ram;
        }
        ' "$FOLDER/energy_cpu_turbostat.log" > "$FOLDER/energy_cpu_watts.csv"
        
        # Calcul des moyennes
        AVG_PKG=$(awk -F';' '$1+0>0 {sum+=$1; count++} END {if(count>0) printf "%.2f", sum/count; else print "N/A"}' "$FOLDER/energy_cpu_watts.csv")
        AVG_CORE=$(awk -F';' '$2+0>0 {sum+=$2; count++} END {if(count>0) printf "%.2f", sum/count; else print "N/A"}' "$FOLDER/energy_cpu_watts.csv")
        AVG_RAM=$(awk -F';' '$3+0>0 {sum+=$3; count++} END {if(count>0) printf "%.2f", sum/count; else print "N/A"}' "$FOLDER/energy_cpu_watts.csv")
        
        echo "Package_Watt;Core_Watt;RAM_Watt" > "$FOLDER/energy_cpu_summary.csv"
        echo "$AVG_PKG;$AVG_CORE;$AVG_RAM" >> "$FOLDER/energy_cpu_summary.csv"
    else
        AVG_PKG="N/A"
        AVG_CORE="N/A"
        AVG_RAM="N/A"
    fi
    
    # Formatage des données énergétiques MACHINE (powerstat)
    if [ "$USE_POWERSTAT" == "true" ] && [ -f "$FOLDER/energy_machine_powerstat.log" ]; then
        echo "[$(date +%H:%M:%S)] 📊 Formatage des données énergétiques MACHINE..."
        
        # Parser powerstat - format attendu : lignes avec "Watts" ou valeurs numériques
        grep -i "watts" "$FOLDER/energy_machine_powerstat.log" | grep -oE "[0-9]+\.[0-9]+" > "$FOLDER/energy_machine_watts.csv"
        
        # Si vide, essayer autre pattern
        if [ ! -s "$FOLDER/energy_machine_watts.csv" ]; then
            awk '/^[[:space:]]*[0-9]+\.[0-9]+/ {print $1}' "$FOLDER/energy_machine_powerstat.log" > "$FOLDER/energy_machine_watts.csv"
        fi
        
        # Chercher la moyenne dans le log
        AVG_MACHINE=$(grep -iE "average|summary" "$FOLDER/energy_machine_powerstat.log" | grep -oE "[0-9]+\.[0-9]+" | head -1)
        
        # Sinon calculer depuis les échantillons
        if [ -z "$AVG_MACHINE" ] && [ -s "$FOLDER/energy_machine_watts.csv" ]; then
            AVG_MACHINE=$(awk '{sum+=$1; count++} END {if(count>0) printf "%.2f", sum/count; else print "N/A"}' "$FOLDER/energy_machine_watts.csv")
        elif [ -z "$AVG_MACHINE" ]; then
            AVG_MACHINE="N/A"
        fi
        
        echo "Machine_Total_Watt" > "$FOLDER/energy_machine_summary.csv"
        echo "$AVG_MACHINE" >> "$FOLDER/energy_machine_summary.csv"
    else
        AVG_MACHINE="N/A"
    fi
    
    # Création d'un fichier de métadonnées
    cat > "$FOLDER/test_metadata.txt" << EOF
Test: $TEST_NAME
Date: $(date '+%Y-%m-%d %H:%M:%S')
Mode: $MODE
Workers: ${WORKERS:-N/A}
Duration: ${TEST_DURATION}s
Ping Duration: ${PING_DURATION}s
Wrk Duration: ${WRK_DURATION}s
Tiger-Fox PID: $APP_PID
Rules File: $RULES
Queue Number: $QUEUE_NUM
Bonus Test: ${IS_BONUS:-false}
EOF
    
    # Listing des fichiers générés (exclure les fichiers vides)
    echo ""
    echo "✅ Test terminé avec succès!"
    echo "   Fichiers générés dans $FOLDER:"
    ls -lh "$FOLDER" | tail -n +2 | awk '$5!="0" {printf "     - %-40s (%s)\n", $9, $5}'
    
    # Affichage des résumés énergétiques
    echo ""
    if [ "$USE_TURBOSTAT" == "true" ] && [ "$AVG_PKG" != "N/A" ]; then
        echo "   ⚡ Consommation énergétique CPU moyenne:"
        echo "      • Package: $AVG_PKG W"
        echo "      • Cores:   $AVG_CORE W"
        echo "      • RAM:     $AVG_RAM W"
    fi
    
    if [ "$USE_POWERSTAT" == "true" ] && [ "$AVG_MACHINE" != "N/A" ]; then
        echo "   🔋 Consommation énergétique MACHINE moyenne:"
        echo "      • Total:   $AVG_MACHINE W"
    fi
    
    sleep 2  # Pause entre les tests
}

# ============================================================================
# TESTS STANDARDS
# ============================================================================

echo ""
echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
echo "┃  PHASE 1: TESTS STANDARDS (Charge normale)                         ┃"
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
echo "┃  PHASE 2: TESTS BONUS (Charge doublée - Wrk boosté)                ┃"
echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
echo ""
echo "⚠️  IMPORTANT: L'injecteur doit utiliser wrk avec -t8 -c1000 pour ces tests!"

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
echo "   2. Récupérer également le dossier de l'injecteur"
echo "   3. Exécuter: python3 analyze_results.py"
echo ""