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
    memory = SQLiteMemory()
    print(f"Database: {memory.db_path}\n")

    # --- Seed Prompts ---
    seeds = memory._query_entries(SeedEntry)
    print(f"=== SeedEntries ({len(seeds)} rows) ===")
    if seeds:
        print(f"  {'Dataset':<25} {'Type':<12} {'Data Type':<10} {'Harm Categories':<30} {'Value'}")
        print("  " + "-" * 120)
        for s in seeds:
            print(
                f"  {_trunc(s.dataset_name, 24):<25} {(s.seed_type or '-'):<12} "
                f"{(s.data_type or '-'):<10} {_trunc(str(s.harm_categories), 28):<30} "
                f"{_trunc(s.value, 50)}"
            )
    print()

    # --- Prompt Memory (conversations) ---
    prompts = memory._query_entries(PromptMemoryEntry)
    print(f"=== PromptMemoryEntries ({len(prompts)} rows) ===")
    if prompts:
        print(f"  {'Conversation ID':<38} {'Role':<12} {'Timestamp':<22} {'Value'}")
        print("  " + "-" * 130)
        for p in prompts:
            ts = str(p.timestamp)[:19] if p.timestamp else "-"
            print(
                f"  {str(p.conversation_id):<38} {(p.role or '-'):<12} "
                f"{ts:<22} {_trunc(p.converted_value, 60)}"
            )
    print()

    # --- Scores ---
    scores = memory._query_entries(ScoreEntry)
    print(f"=== ScoreEntries ({len(scores)} rows) ===")
    if scores:
        print(f"  {'Score Type':<15} {'Value':<10} {'Category':<20} {'Rationale'}")
        print("  " + "-" * 100)
        for sc in scores:
            print(
                f"  {(sc.score_type or '-'):<15} {(sc.score_value or '-'):<10} "
                f"{_trunc(str(sc.score_category), 18):<20} {_trunc(sc.score_rationale, 60)}"
            )
    print()

    # --- Attack Results ---
    attacks = memory._query_entries(AttackResultEntry)
    print(f"=== AttackResultEntries ({len(attacks)} rows) ===")
    if attacks:
        print(f"  {'Outcome':<15} {'Turns':>6}  {'Time(ms)':>10}  {'Objective'}")
        print("  " + "-" * 100)
        for a in attacks:
            print(
                f"  {(a.outcome or '-'):<15} {a.executed_turns or 0:>6}  "
                f"{a.execution_time_ms or 0:>10}  {_trunc(a.objective, 60)}"
            )
    print()

    # --- Scenario Results ---
    scenarios = memory._query_entries(ScenarioResultEntry)
    print(f"=== ScenarioResultEntries ({len(scenarios)} rows) ===")
    if scenarios:
        print(f"  {'Scenario':<30} {'State':<15} {'Tries':>6}  {'Timestamp'}")
        print("  " + "-" * 80)
        for sr in scenarios:
            ts = str(sr.timestamp)[:19] if sr.timestamp else "-"
            print(
                f"  {_trunc(sr.scenario_name, 28):<30} {(sr.scenario_run_state or '-'):<15} "
                f"{sr.number_tries or 0:>6}  {ts}"
            )
    print()


main()
