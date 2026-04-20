#!/data/data/com.termux/files/usr/bin/bash
# ─── AI Secret Scanner — Universal Launcher ───────────────────────────────────
# Works from ANY directory. Just run:  bash ~/justlurkingaround/start.sh

# Resolve the directory this script lives in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR" || {
  echo "  [!] Could not cd into $SCRIPT_DIR"
  exit 1
}

# Quick sanity check
if [ ! -f "package.json" ]; then
  echo "  [!] package.json not found in $SCRIPT_DIR"
  echo "  Run: git clone https://github.com/justlurking-around/justlurkingaround.git"
  exit 1
fi

# Install deps if node_modules missing
if [ ! -d "node_modules" ]; then
  echo "  [*] node_modules not found — running install..."
  bash install-termux.sh
fi

# Start the self-healing daemon in background if not already running
if [ "${DISABLE_HEAL:-false}" != "true" ]; then
  if ! pgrep -f "scripts/heal.js" > /dev/null 2>&1; then
    node scripts/heal.js > logs/heal.log 2>&1 &
    echo "  [OK] Self-healing daemon started (PID $!)"
  fi
fi

exec node src/cli/index.js "$@"
