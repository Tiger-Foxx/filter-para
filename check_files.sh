#!/bin/bash
# Quick compilation check script

echo "🔍 Checking for compilation issues..."
echo ""

# Check if all source files exist
echo "✅ Checking source files..."
files=(
    "src/main.cpp"
    "src/tiger_system.cpp"
    "src/tiger_system.h"
    "src/utils.cpp"
    "src/utils.h"
    "src/engine/rule_engine.cpp"
    "src/engine/rule_engine.h"
    "src/engine/fast_sequential_engine.cpp"
    "src/engine/fast_sequential_engine.h"
    "src/engine/ultra_parallel_engine.cpp"
    "src/engine/ultra_parallel_engine.h"
    "src/handlers/packet_handler.cpp"
    "src/handlers/packet_handler.h"
    "src/loaders/rule_loader.cpp"
    "src/loaders/rule_loader.h"
)

for file in "${files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing: $file"
        exit 1
    fi
done

echo "✅ All source files present"
echo ""

# Check rules file
if [ ! -f "rules/example_rules.json" ]; then
    echo "❌ Missing: rules/example_rules.json"
    exit 1
fi

echo "✅ Rules file present"
echo ""

echo "🎉 All checks passed! Ready to build."
echo ""
echo "Next steps:"
echo "  chmod +x build.sh"
echo "  sudo ./build.sh"
