#!/bin/bash

echo "=========================================================="
echo "  THREAT: RED TEAMING MULTI-TURN (DOCKER EXEC)            "
echo "=========================================================="

# 1. Run the attack script and evaluation automatically
echo "[+] PHASE 1: LAUNCHING MULTI-TURN ATTACKS & SCORING (VIA DOCKER EXEC)"

sudo docker exec -e PROMPTINTEL_API_KEY="$PROMPTINTEL_API_KEY" -w /app/fintech_ai_audit pyrit-jupyter python main_audit.py --threats red_teaming_multiturn --max-prompts 5 --report-formats html 

# --- SAFETY CHECK ---
if [ $? -ne 0 ]; then
	echo "[-] ERROR: Audit pipeline failed! Halting."
	exit 1
fi
# --------------------

echo "=========================================================="
echo "         THREAT AUDIT FULLY COMPLETE                      "
echo "=========================================================="
