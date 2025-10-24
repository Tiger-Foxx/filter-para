#!/bin/bash

################################################################################
# Script d'évaluation MANUEL côté FILTREUR
# Usage: ./eval_mini.sh <mode> [workers]
# Exemples:
#   ./eval_mini.sh sequential
#   ./eval_mini.sh parallel 4
################################################################################

MODE="$1"
WORKERS="$2"
RULES="/users/The_Fox/filter-para/rules/example_rules_backup2.json"
QUEUE_NUM=0
DURATION=75  # 75s = 20s ping + 50s wrk + marges

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

# Configuration du dossier et de la commande
BUILD_DIR="$(pwd)/build"
TIGER_FOX="$BUILD_DIR/tiger-fox"

if [ ! -f "$TIGER_FOX" ]; then
    echo "❌ ERREUR: tiger-fox non trouvé dans $BUILD_DIR"
    exit 1
fi

if [ "$MODE" == "parallel" ]; then
    FOLDER="execution_mode_parallel_${WORKERS}_workers"
    CMD="sudo $TIGER_FOX --mode parallel --rules $RULES --workers $WORKERS --queue-num $QUEUE_NUM"
    TEST_NAME="Mode PARALLEL avec $WORKERS workers"
else
    FOLDER="execution_mode_sequential"
    CMD="sudo $TIGER_FOX --mode sequential --rules $RULES --queue-num $QUEUE_NUM"
    TEST_NAME="Mode SEQUENTIAL"
fi

# Vérifications des outils énergétiques
USE_TURBOSTAT=false
USE_POWERSTAT=false

if command -v turbostat &> /dev/null; then
    USE_TURBOSTAT=true
fi

if command -v powerstat &> /dev/null; then
    USE_POWERSTAT=true
fi

mkdir -p "$FOLDER"
cd "$FOLDER"

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  ÉVALUATION MANUELLE - FILTREUR                                        ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Test: $TEST_NAME"
echo "📁 Dossier: $FOLDER"
echo "⏱️  Durée: ${DURATION}s"
echo ""

# Nettoyage
sudo pkill -9 tiger-fox 2>/dev/null || true
sleep 1

# Démarrage des moniteurs
echo "[$(date +%H:%M:%S)] 📊 Démarrage des moniteurs CPU..."
mpstat -P ALL 1 $DURATION | awk 'BEGIN{FS=" ";OFS=";"} /^[0-9]+:[0-9]+:[0-9]+/ && !/Linux/ && !/^$/ {gsub(/^ +| +$/,"",$3); print $3,$4,$5,$6,$7,$8,$9,$10,$11,$12}' > cpu_all.csv &
MPSTAT_PID=$!

# Lancer Tiger-Fox
echo "[$(date +%H:%M:%S)] 🦊 Lancement de Tiger-Fox..."
$CMD > tiger_fox_output.log 2>&1 &
APP_PID=$!

sleep 3

if ! ps -p $APP_PID > /dev/null; then
    echo "❌ ERREUR: Tiger-Fox s'est arrêté!"
    cat tiger_fox_output.log
    exit 1
fi

echo "[$(date +%H:%M:%S)] ✅ Tiger-Fox opérationnel (PID: $APP_PID)"

# Moniteur CPU du processus
pidstat -p $APP_PID 1 $DURATION | awk 'BEGIN{FS=" ";OFS=";"} /^[0-9]+:[0-9]+:[0-9]+/ && !/Linux/ && !/Average/ {print $1,$4,$5,$6,$7,$8}' > cpu_app.csv &
PIDSTAT_PID=$!

# CPU à intervalles
top -b -d 1 -n $DURATION | grep --line-buffered "Cpu(s)" | awk '{print $2}' > cpu_log_interval.csv &
TOP_PID=$!

# Énergie CPU (turbostat)
if [ "$USE_TURBOSTAT" == "true" ]; then
    echo "[$(date +%H:%M:%S)] ⚡ Mesure énergétique CPU (turbostat)..."
    sudo turbostat --quiet --show PkgWatt,CorWatt,RAMWatt --interval 1 sleep $DURATION > energy_cpu_turbostat.log 2>&1 &
    TURBOSTAT_PID=$!
fi

# Énergie MACHINE (powerstat)
if [ "$USE_POWERSTAT" == "true" ]; then
    echo "[$(date +%H:%M:%S)] 🔋 Mesure énergétique MACHINE (powerstat)..."
    sudo powerstat -R -d 0 1 $DURATION > energy_machine_powerstat.log 2>&1 &
    POWERSTAT_PID=$!
fi

echo "[$(date +%H:%M:%S)] ⏳ Collecte des métriques (${DURATION}s)..."
echo "                      >>> Lancez maintenant eval_inj_mini.sh sur l'injecteur <<<"
echo ""

# Attente
sleep $DURATION

# Arrêt
echo "[$(date +%H:%M:%S)] 🛑 Arrêt de Tiger-Fox..."
sudo kill -SIGINT $APP_PID 2>/dev/null || true
sleep 2
sudo kill -SIGKILL $APP_PID 2>/dev/null || true

# Attente des moniteurs
wait $MPSTAT_PID 2>/dev/null || true
wait $PIDSTAT_PID 2>/dev/null || true
wait $TOP_PID 2>/dev/null || true
[ -n "$TURBOSTAT_PID" ] && wait $TURBOSTAT_PID 2>/dev/null || true
[ -n "$POWERSTAT_PID" ] && wait $POWERSTAT_PID 2>/dev/null || true

# Formatage énergie CPU
if [ "$USE_TURBOSTAT" == "true" ] && [ -f "energy_cpu_turbostat.log" ]; then
    echo "[$(date +%H:%M:%S)] 📊 Formatage données CPU..."
    awk 'BEGIN { pkg_col=0; cor_col=0; ram_col=0; }
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
    }' energy_cpu_turbostat.log > energy_cpu_watts.csv
    
    AVG_PKG=$(awk -F';' '$1+0>0 {sum+=$1; count++} END {if(count>0) printf "%.2f", sum/count; else print "N/A"}' energy_cpu_watts.csv)
    AVG_CORE=$(awk -F';' '$2+0>0 {sum+=$2; count++} END {if(count>0) printf "%.2f", sum/count; else print "N/A"}' energy_cpu_watts.csv)
    AVG_RAM=$(awk -F';' '$3+0>0 {sum+=$3; count++} END {if(count>0) printf "%.2f", sum/count; else print "N/A"}' energy_cpu_watts.csv)
    
    echo "Package_Watt;Core_Watt;RAM_Watt" > energy_cpu_summary.csv
    echo "$AVG_PKG;$AVG_CORE;$AVG_RAM" >> energy_cpu_summary.csv
fi

# Formatage énergie MACHINE
if [ "$USE_POWERSTAT" == "true" ] && [ -f "energy_machine_powerstat.log" ]; then
    echo "[$(date +%H:%M:%S)] 📊 Formatage données MACHINE..."
    grep -i "watts" energy_machine_powerstat.log | grep -oE "[0-9]+\.[0-9]+" > energy_machine_watts.csv
    
    if [ ! -s "energy_machine_watts.csv" ]; then
        awk '/^[[:space:]]*[0-9]+\.[0-9]+/ {print $1}' energy_machine_powerstat.log > energy_machine_watts.csv
    fi
    
    AVG_MACHINE=$(grep -iE "average|summary" energy_machine_powerstat.log | grep -oE "[0-9]+\.[0-9]+" | head -1)
    
    if [ -z "$AVG_MACHINE" ] && [ -s "energy_machine_watts.csv" ]; then
        AVG_MACHINE=$(awk '{sum+=$1; count++} END {if(count>0) printf "%.2f", sum/count; else print "N/A"}' energy_machine_watts.csv)
    elif [ -z "$AVG_MACHINE" ]; then
        AVG_MACHINE="N/A"
    fi
    
    echo "Machine_Total_Watt" > energy_machine_summary.csv
    echo "$AVG_MACHINE" >> energy_machine_summary.csv
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════════════╗"
echo "║  ✅ TEST TERMINÉ!                                                      ║"
echo "╚════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📁 Résultats dans: $(pwd)"
echo ""
echo "📊 Fichiers générés:"
ls -lh | tail -n +2 | awk '$5!="0" {printf "   - %-40s (%s)\n", $9, $5}'

if [ "$USE_TURBOSTAT" == "true" ] && [ "$AVG_PKG" != "N/A" ]; then
    echo ""
    echo "⚡ Consommation CPU moyenne:"
    echo "   Package: $AVG_PKG W | Cores: $AVG_CORE W | RAM: $AVG_RAM W"
fi

if [ "$USE_POWERSTAT" == "true" ] && [ "$AVG_MACHINE" != "N/A" ]; then
    echo ""
    echo "🔋 Consommation MACHINE moyenne: $AVG_MACHINE W"
fi

echo ""
