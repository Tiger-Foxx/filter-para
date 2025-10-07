#!/bin/bash

# Script pour supprimer tous les fichiers markdown sauf README.md

echo "🧹 Cleaning up markdown files..."

# Find and delete all .md files except README.md
find . -type f \( -name "*.md" -o -name "*.MD" \) ! -name "README.md" -delete

echo "✅ Cleaned up! Only README.md remains."

# List remaining markdown files
echo ""
echo "📄 Remaining markdown files:"
find . -type f \( -name "*.md" -o -name "*.MD" \)
