import sys
from io import StringIO

from pyrit.memory import SQLiteMemory
from pyrit.memory.memory_models import (
    AttackResultEntry,
    PromptMemoryEntry,
    ScenarioResultEntry,
    ScoreEntry,
    SeedEntry,
)


def _trunc(value: str | None, max_len: int = 80) -> str:
    if not value:
        return "-"
    value = value.replace("\n", " ")
    return value[:max_len] + "..." if len(value) > max_len else value


def main() -> None:
    output = StringIO()

    def out(msg: str = "") -> None:
        print(msg)
        output.write(msg + "\n")

    memory = SQLiteMemory()
    out(f"Database: {memory.db_path}\n")

    # --- Seed Prompts ---
    seeds = memory._query_entries(SeedEntry)
    out(f"=== SeedEntries ({len(seeds)} rows) ===")
    if seeds:
        out(f"  {'Dataset':<25} {'Type':<12} {'Data Type':<10} {'Harm Categories':<30} {'Value'}")
        out("  " + "-" * 120)
        for s in seeds:
            out(
                f"  {_trunc(s.dataset_name, 24):<25} {(s.seed_type or '-'):<12} "
                f"{(s.data_type or '-'):<10} {_trunc(str(s.harm_categories), 28):<30} "
                f"{_trunc(s.value, 50)}"
            )
    out()

    # --- Prompt Memory (conversations) ---
    prompts = memory._query_entries(PromptMemoryEntry)
    out(f"=== PromptMemoryEntries ({len(prompts)} rows) ===")
    if prompts:
        out(f"  {'Conversation ID':<38} {'Role':<12} {'Timestamp':<22} {'Value'}")
        out("  " + "-" * 130)
        for p in prompts:
            ts = str(p.timestamp)[:19] if p.timestamp else "-"
            out(
                f"  {str(p.conversation_id):<38} {(p.role or '-'):<12} "
                f"{ts:<22} {_trunc(p.converted_value, 60)}"
            )
    out()

    # --- Scores ---
    scores = memory._query_entries(ScoreEntry)
    out(f"=== ScoreEntries ({len(scores)} rows) ===")
    if scores:
        out(f"  {'Score Type':<15} {'Value':<10} {'Category':<20} {'Rationale'}")
        out("  " + "-" * 100)
        for sc in scores:
            out(
                f"  {(sc.score_type or '-'):<15} {(sc.score_value or '-'):<10} "
                f"{_trunc(str(sc.score_category), 18):<20} {_trunc(sc.score_rationale, 60)}"
            )
    out()

    # --- Attack Results ---
    attacks = memory._query_entries(AttackResultEntry)
    out(f"=== AttackResultEntries ({len(attacks)} rows) ===")
    if attacks:
        out(f"  {'Outcome':<15} {'Turns':>6}  {'Time(ms)':>10}  {'Objective'}")
        out("  " + "-" * 100)
        for a in attacks:
            out(
                f"  {(a.outcome or '-'):<15} {a.executed_turns or 0:>6}  "
                f"{a.execution_time_ms or 0:>10}  {_trunc(a.objective, 60)}"
            )
    out()

    # --- Scenario Results ---
    scenarios = memory._query_entries(ScenarioResultEntry)
    out(f"=== ScenarioResultEntries ({len(scenarios)} rows) ===")
    if scenarios:
        out(f"  {'Scenario':<30} {'State':<15} {'Tries':>6}  {'Timestamp'}")
        out("  " + "-" * 80)
        for sr in scenarios:
            ts = str(sr.timestamp)[:19] if sr.timestamp else "-"
            out(
                f"  {_trunc(sr.scenario_name, 28):<30} {(sr.scenario_run_state or '-'):<15} "
                f"{sr.number_tries or 0:>6}  {ts}"
            )
    out()

    # Write results to file
    output_path = "fintech_ai_audit/stored_data_report.txt"
    with open(output_path, "w") as f:
        f.write(output.getvalue())
    print(f"Results written to {output_path}")


main()
