#!/bin/bash

echo "=========================================================="
echo "  THREAT: INSECURE CODE GENERATION (DOCKER EXEC)          "
echo "=========================================================="

# 1. Run the attack script inside your existing Jupyter container
echo "[+] PHASE 1: LAUNCHING ATTACKS (VIA DOCKER EXEC)"
# if [ -n "$1" ]; then
    echo "[+] Limiting attack to $1 prompts"
    sudo docker exec -w /app/fintech_ai_audit pyrit-jupyter python main_audit.py --threats insecure_code_generation --ignore-judge --max-prompts "2"
# else
#     sudo docker exec -w /app/fintech_ai_audit pyrit-jupyter python main_audit.py --threats insecure_code_generation --ignore-judge
# fi

# --- SAFETY CHECK ---
if [ $? -ne 0 ]; then
    echo "[-] ERROR: Phase 1 (Attack) failed! Halting pipeline."
    exit 1
fi
# --------------------

# Wait for container to close and Ollama to flush VRAM
echo "[+] Flushing VRAM..."
sleep 5

# 2. Read the generated UUID from the state file 
RUN_ID=$(cat latest_run_id.txt)
echo "[+] Target LLM unloaded. Target Run ID: $RUN_ID"

# 3. Run the evaluation script inside your existing Jupyter container
echo "[+] PHASE 2: BATCH EVALUATION (VIA DOCKER EXEC)"
sudo docker exec  -w /app/fintech_ai_audit pyrit-jupyter python batch_score.py --run_id "$RUN_ID" --threat insecure_code_generation

# --- SAFETY CHECK ---
if [ $? -ne 0 ]; then
    echo "[-] ERROR: Phase 2 (Evaluation) failed! Halting pipeline."
    exit 1
fi
# --------------------

echo "=========================================================="
echo "         THREAT AUDIT FULLY COMPLETE                      "
echo "=========================================================="

