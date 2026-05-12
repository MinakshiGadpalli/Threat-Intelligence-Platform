#!/bin/bash

PROJECT_DIR="$HOME/Desktop/Threat-Intelligence-Platform-TIP-"
LOG_DIR="$PROJECT_DIR/logs"
mkdir -p "$LOG_DIR"

echo "=========================================================="
echo "            THREAT INTEL PLATFORM                  "
echo "=========================================================="
echo ""

# ==========================================
# 1. SYSTEM SETUP 
# ==========================================
echo "[SYSTEM SETUP] Starting Databases & Environment..."
sudo docker start tip_mongodb tip_elasticsearch tip_kibana
sleep 5
cd "$PROJECT_DIR" || exit
source venv/bin/activate
echo "[SYSTEM SETUP] Infrastructure is Ready!"
echo ""

# ==========================================
# 2. WEEK 1: OSINT DATA COLLECTION
# ==========================================
echo "----------------------------------------------------------"
echo "   WEEK 1: OSINT DATA COLLECTION "
echo "----------------------------------------------------------"
python3 week1_osint/feed_collector.py
echo "-> ✅ Week 1 Execution Complete."
echo ""

# ==========================================
# 3. WEEK 2: DATA PROCESSING & SIEM
# ==========================================
echo "----------------------------------------------------------"
echo "   WEEK 2: DATA NORMALIZATION & SIEM "
echo "----------------------------------------------------------"
python3 week2_siem/normalizer.py
python3 week2_siem/elk_pusher.py
echo "-> ✅ Week 2 Execution Complete."
echo ""

# ==========================================
# 4. WEEK 4: ALERTS & DASHBOARD 
# ==========================================
echo "----------------------------------------------------------"
echo "   WEEK 4: ALERTS & DASHBOARD AUDIT "
echo "----------------------------------------------------------"
pkill -f alert_manager.py
nohup python3 week4_dashboard/alert_manager.py > "$LOG_DIR/alert.log" 2>&1 &

echo "-> TIP Dashboard is LIVE at: http://localhost:5601"
echo "-> Fetching Current Blocked IPs & Audit Table:"
echo ".........................................................."
LIST_OUTPUT=$(python3 week4_dashboard/rollback_manager.py list)
echo "$LIST_OUTPUT"
echo ".........................................................."
echo ""

# ==========================================
# 5. WEEK 3: POLICY ENFORCEMENT DAEMON (NEW TERMINAL)
# ==========================================
echo "----------------------------------------------------------"
echo "   WEEK 3: FIREWALL ENFORCEMENT (NEW TERMINAL) "
echo "----------------------------------------------------------"
pkill -f policy_daemon.py
gnome-terminal --title="Week 3: LIVE Policy Daemon" -- bash -c "cd '$PROJECT_DIR'; source venv/bin/activate; python3 week3_enforcer/policy_daemon.py; exec bash"
echo "-> Policy Daemon is now active in a separate window!"
echo ""

# ==========================================
# 6. AUTOMATIC RANDOM IP UNBLOCK
# ==========================================
echo "=========================================================="
echo "   STEP 6: AUTOMATIC RANDOM IP UNBLOCK"
echo "=========================================================="
echo "-> Scanning the list for a random IP address..."

# Extract valid IPs from the list output, filter unique ones, and pick 1 randomly
RANDOM_IP=$(echo "$LIST_OUTPUT" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u | shuf -n 1)

if [ -n "$RANDOM_IP" ]; then
    echo "-> Target IP Selected: $RANDOM_IP"
    echo "-> Executing Unblock Action..."
    echo ""
    # Run the unblock command with Mitesh as the actor
    python3 week4_dashboard/rollback_manager.py unblock "$RANDOM_IP" --actor "Mitesh" --reason "Automated Startup Test"
else
    echo "-> Warning: No valid IP addresses found in the block list to unblock."
fi

echo ""
echo "=========================================================="
echo " ✅ System is Fully LIVE! Check Kibana for the dashboard. "
echo "=========================================================="
