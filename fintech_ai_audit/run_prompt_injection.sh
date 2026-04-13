#!/bin/bash

echo "=========================================================="
echo "  THREAT: PROMPT INJECTION (DOCKER EXEC)                  "
echo "=========================================================="

# 1. Run the attack script and evaluation automatically
echo "[+] PHASE 1: LAUNCHING ATTACKS & SCORING (VIA DOCKER EXEC)"
# if [ -n "$1" ]; then
	# echo "[+] Limiting attack to $1 prompts"
	sudo docker exec -e PROMPTINTEL_API_KEY="$PROMPTINTEL_API_KEY" -w /app/fintech_ai_audit pyrit-jupyter python main_audit.py --threats prompt_injection --ignore-judge --batch-score
# else
# 	sudo docker exec -e PROMPTINTEL_API_KEY="$PROMPTINTEL_API_KEY" -w /app/fintech_ai_audit pyrit-jupyter python main_audit.py --threats prompt_injection --ignore-judge --batch-score
# fi

# --- SAFETY CHECK ---
if [ $? -ne 0 ]; then
	echo "[-] ERROR: Audit pipeline failed! Halting."
	exit 1
fi
# --------------------

echo "=========================================================="
echo "         THREAT AUDIT FULLY COMPLETE                      "
echo "=========================================================="
