#!/bin/bash

MODE="$1"
WORKERS="$2"
RULES="rules/example_rules_backup2.json"
QUEUE_NUM=0
DURATION=90

if [ "$MODE" == "parallel" ]; then
    FOLDER="execution_mode_parallel_${WORKERS}_workers"
    CMD="sudo $(pwd)/build/tiger-fox --mode parallel --rules $RULES --workers $WORKERS --queue-num $QUEUE_NUM"
else
    FOLDER="execution_mode_sequential"
    CMD="sudo $(pwd)/build/tiger-fox --mode sequential --rules $RULES --queue-num $QUEUE_NUM"
fi

mkdir -p "$FOLDER"
cd "$FOLDER"

echo "Démarrage du benchmark ($MODE)..."

# CPU global et par cœur en CSV
mpstat -P ALL 1 $DURATION | awk 'BEGIN{FS=" ";OFS=";"} /[0-9]+:[0-9]+:[0-9]+/ {print $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14}' > cpu_all.csv &
MPSTAT_PID=$!

# Lancer le programme
$CMD &
APP_PID=$!

sleep 2  # Laisse le programme démarrer

# CPU du programme en CSV
pidstat -p $APP_PID 1 $DURATION | awk 'BEGIN{FS=" ";OFS=";"} /[0-9]+/ {print $1,$2,$3,$4,$5,$6,$7,$8,$9,$10}' > cpu_app.csv &

# Log CPU général à intervalles
top -b -d 1 -n $DURATION | grep --line-buffered "Cpu(s)" | awk '{print $2}' > cpu_log_interval.csv &

# Attendre la fin du benchmark
sleep $DURATION

# Arrêt propre du programme
sudo kill -SIGINT $APP_PID
sleep 2
sudo kill -SIGTSTP $APP_PID  # Si besoin, force l'arrêt

wait $MPSTAT_PID

echo "Benchmark terminé. Fichiers générés dans $FOLDER :"
echo "  - cpu_all.csv (CPU général et par cœur, CSV)"
echo "  - cpu_app.csv (CPU du programme, CSV)"
echo "  - cpu_log_interval.csv (CPU général à intervalles, CSV)"