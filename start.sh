#!/data/data/com.termux/files/usr/bin/bash
# ─── AI Secret Scanner — Universal Launcher ───────────────────────────────────
# Works from ANY directory: bash ~/justlurkingaround/start.sh
# Survives terminal close on Termux (heal daemon runs in background via nohup)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "  [!] Cannot cd into $SCRIPT_DIR"; exit 1; }

# Sanity check
if [ ! -f "package.json" ]; then
  echo "  [!] package.json not found — run: git clone https://github.com/justlurking-around/justlurkingaround.git"
  exit 1
fi

# Install deps if missing
if [ ! -d "node_modules" ]; then
  echo "  [*] First run — installing dependencies..."
  bash install-termux.sh
fi

# Ensure dirs exist
mkdir -p data logs reports

# ─── Start self-healing daemon in background ──────────────────────────────────
# Uses nohup + disown so it keeps running if terminal closes on Termux
if [ "${DISABLE_HEAL:-false}" != "true" ]; then
  # Kill any existing heal daemon first (stale PID)
  HEAL_PID_FILE="data/.heal.pid"
  if [ -f "$HEAL_PID_FILE" ]; then
    OLD_PID=$(cat "$HEAL_PID_FILE")
    kill "$OLD_PID" 2>/dev/null && echo "  [*] Stopped old heal daemon (PID $OLD_PID)"
    rm -f "$HEAL_PID_FILE"
  fi

  # DAEMON mode: no --once flag = stays alive, interval fires every 30min
  # AUTO_FIX_DEPS=true  = npm audit fix + patch updates auto-committed
  # WATCH_PROCESS=false = we don't restart the scanner from here
  AUTO_FIX_DEPS=true WATCH_PROCESS=false nohup node scripts/heal.js >> logs/heal.log 2>&1 &
  HEAL_PID=$!
  echo $HEAL_PID > "$HEAL_PID_FILE"
  disown $HEAL_PID
  echo "  [OK] Self-heal daemon started (PID=$HEAL_PID, cycle=30min)"
  echo "       Logs: tail -f logs/heal.log"
fi

# ─── Launch the scanner ───────────────────────────────────────────────────────
echo ""
exec node src/cli/index.js "$@"
