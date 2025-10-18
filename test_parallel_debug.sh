#!/bin/bash

echo "🧪 ====================================="
echo "   TEST MODE PARALLÈLE AVEC DEBUG"
echo "====================================="
echo ""

# Vérifier qu'on est root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Erreur: Ce script doit être exécuté avec sudo"
    exit 1
fi

echo "📋 Configuration iptables..."
iptables -F FORWARD
iptables -A FORWARD -i eno2 -o enp5s0f0 -j ACCEPT
iptables -A FORWARD -i enp5s0f0 -o eno2 -j NFQUEUE --queue-num 0
echo "✅ iptables configuré"
echo ""

echo "🚀 Lancement du filtre en mode PARALLEL avec VERBOSE..."
echo "   (Appuyez sur Ctrl+C pour arrêter)"
echo ""
echo "-----------------------------------"

./build/tiger-fox --mode parallel --workers 3 --queue-num 0 --verbose

echo ""
echo "🧹 Nettoyage iptables..."
iptables -F FORWARD
echo "✅ Terminé"
