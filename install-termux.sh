#!/data/data/com.termux/files/usr/bin/bash
# ─── AI Secret Scanner — Termux Install Script ────────────────────────────────
# Run this once after cloning:  bash install-termux.sh

set -e

echo ""
echo "  +==================================================+"
echo "  |   AI Secret Scanner — Termux Setup               |"
echo "  +==================================================+"
echo ""

# Check Node.js
if ! command -v node &>/dev/null; then
  echo "  [!] Node.js not found. Installing..."
  pkg install nodejs -y
fi

NODE_VER=$(node -e "process.stdout.write(process.version)")
echo "  [OK] Node.js $NODE_VER"

# Check git
if ! command -v git &>/dev/null; then
  pkg install git -y
fi
echo "  [OK] git $(git --version | cut -d' ' -f3)"

# Install npm deps
# --ignore-scripts skips native builds (better-sqlite3 will fail on Termux)
# sql.js (pure WASM) is used automatically instead
echo ""
echo "  Installing dependencies..."
echo "  (better-sqlite3 will be skipped — sql.js WASM used instead)"
echo ""

npm install --ignore-scripts 2>&1 | grep -v "^npm warn\|^npm notice" || true

# Verify sql.js loaded
node -e "require('sql.js'); console.log('  [OK] sql.js (WASM SQLite) available')"

# Create data dir
mkdir -p data logs reports

# ── Add convenient aliases so you can run from anywhere ─────────────────────
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RC_FILE="$HOME/.bashrc"

# Add alias if not already present
if ! grep -q 'alias scanner=' "$RC_FILE" 2>/dev/null; then
  echo "" >> "$RC_FILE"
  echo "# AI Secret Scanner" >> "$RC_FILE"
  echo "alias scanner='bash $INSTALL_DIR/start.sh'" >> "$RC_FILE"
  echo "alias scanner-update='bash $INSTALL_DIR/update.sh'" >> "$RC_FILE"
  echo "alias scanner-logs='tail -f $INSTALL_DIR/logs/scanner.log'" >> "$RC_FILE"
  echo "  [OK] Aliases added to $RC_FILE"
  echo "       scanner         — start the app"
  echo "       scanner-update  — pull latest + install deps"
  echo "       scanner-logs    — follow live log"
else
  echo "  [OK] Aliases already in $RC_FILE"
fi

echo ""
echo "  +==================================================+"
echo "  |   Setup complete!                                 |"
echo "  |                                                   |"
echo "  |   Option 1 (from this folder):                    |"
echo "  |     npm start                                     |"
echo "  |                                                   |"
echo "  |   Option 2 (from ANYWHERE after restarting):      |"
echo "  |     source ~/.bashrc && scanner                   |"
echo "  |   or just type: scanner                           |"
echo "  +==================================================+"
echo ""
echo "  Tip: First run will ask for your GitHub token."
echo "  Get one at: github.com/settings/tokens"
echo "  Scope needed: public_repo"
echo ""
