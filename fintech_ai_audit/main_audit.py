import asyncio
import argparse
import logging
import os
import uuid
from pathlib import Path

from pyrit.setup import SQLITE, initialize_pyrit_async
from pyrit.prompt_target import OpenAIChatTarget

# Import your dynamic registry from the scenarios folder
from scenarios import THREAT_REGISTRY

# Enable detailed system logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

async def main(
    *,
    requested_threats: list[str],
    ignore_judge: bool = False,
    max_prompts: int | None = None,
) -> None:
    # 1. Initialize PyRIT and automatically load the .env file
    # This guarantees all generated prompts are saved to your local disk
    config_path = Path("/app/fintech_ai_audit/config.env")
    await initialize_pyrit_async(
            memory_db_type=SQLITE,
            env_files = [config_path]
            )
    current_run_id = str(uuid.uuid4())

    print(f"\n=== STARTING FINTECH AI AUDIT (RUN ID: {current_run_id}) ===")

    # =====================================================================
    # 2. DYNAMICALLY LOAD AGENTS FROM .ENV
    # =====================================================================
    print("Loading AI Agents from environment variables...")
    target_llm = OpenAIChatTarget(
        endpoint=os.environ.get("TARGET_LLM_ENDPOINT"),
        model_name=os.environ.get("TARGET_LLM_MODEL"),
        api_key=os.environ.get("TARGET_LLM_KEY")
    )
    
    # 2. CONDITIONALLY LOAD THE JUDGE LLM
    judge_llm = None
    if not ignore_judge:
        print("Loading Judge AI Agent for Live Scoring...")
        judge_llm = OpenAIChatTarget(
            endpoint=os.environ.get("JUDGE_LLM_ENDPOINT"),
            model_name=os.environ.get("JUDGE_LLM_MODEL"),
            api_key=os.environ.get("JUDGE_LLM_KEY")
        )
    else:
        print("Ignoring Judge AI Agent to preserve GPU VRAM...")


    # =====================================================================
    # 3. FILTER THE REGISTRY BASED ON TERMINAL INPUT
    # =====================================================================
    threats_to_run = []
    if "all" in requested_threats:
        threats_to_run = list(THREAT_REGISTRY.values())
    else:
        for threat_name in requested_threats:
            if threat_name in THREAT_REGISTRY:
                threats_to_run.append(THREAT_REGISTRY[threat_name])
            else:
                print(f"Warning: Threat '{threat_name}' not found in registry. Skipping.")

    # =====================================================================
    # 4. SEQUENTIAL EXECUTION LOOP (Hardware Safe)
    # =====================================================================
    print(f"\n=== LAUNCHING {len(threats_to_run)} SINGLE-TURN THREATS ===")

    # The 'await' in this loop guarantees strict sequential execution of the threats [8]
    for threat_class in threats_to_run:
        threat_name = threat_class.__name__
        print(f"\n--> Executing: {threat_name}...")

        # Instantiate the specific threat scenario from the registry
        scenario_instance = threat_class()

        # Pass the SPECIFIC target llm, judge llm  and the run id down to your threat's execute method!
        await scenario_instance.execute(
                target_llm=target_llm,
                judge_llm=judge_llm,
            run_id=current_run_id,
            max_prompts=max_prompts,
            )
            

    # 5. SAVE THE RUN ID: Write it to a file so your .sh script can read it!
    with open("latest_run_id.txt", "w") as f:
        f.write(current_run_id)

    print(f"\n=== AUDIT COMPLETE ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fully Parameterized Single-Turn AI Audit")

    # Accept specific threats from the registry or run 'all'
    parser.add_argument(
        "--threats", 
        nargs='+', 
        default=["all"], 
        help=f"Specify threats to run: {list(THREAT_REGISTRY.keys())} or 'all'"
    )
    parser.add_argument(
        "--ignore-judge",
        action="store_true",
        help="Do not load the Judge LLM into memory (Use for Batch Scoring)."
    )
    parser.add_argument(
        "--max-prompts",
        type=int,
        default=None,
        help="Limit how many prompts are executed per threat attack.",
    )
    args = parser.parse_args()

    if args.max_prompts is not None and args.max_prompts <= 0:
        parser.error("--max-prompts must be greater than 0")

    asyncio.run(
        main(
            requested_threats=args.threats,
            ignore_judge=args.ignore_judge,
            max_prompts=args.max_prompts,
        )
    )
