#!/data/data/com.termux/files/usr/bin/bash
# ─── AI Secret Scanner — Update Script ────────────────────────────────────────
# Run from anywhere:  bash ~/justlurkingaround/update.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  +==================================================+"
echo "  |   AI Secret Scanner — Update                     |"
echo "  +==================================================+"
echo ""

echo "  [*] Pulling latest changes..."
git pull origin main

echo "  [*] Installing new dependencies..."
# Use --ignore-scripts for Termux compatibility
npm install --ignore-scripts 2>&1 | grep -v "^npm warn\|^npm notice" || true

echo ""
echo "  [OK] Update complete! Run: bash start.sh"
echo ""
