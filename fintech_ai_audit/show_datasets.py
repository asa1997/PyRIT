import asyncio
from pathlib import Path

from pyrit.datasets import SeedDatasetProvider
from pyrit.setup import IN_MEMORY, initialize_pyrit_async


async def main() -> None:
    config_path = Path("/app/fintech_ai_audit/config.env")
    await initialize_pyrit_async(memory_db_type=IN_MEMORY, env_files=[config_path])

    # List all registered dataset names
    all_names = SeedDatasetProvider.get_all_dataset_names()
    print(f"Total datasets available: {len(all_names)}\n")

    # Fetch all datasets with full metadata
    datasets = await SeedDatasetProvider.fetch_datasets_async(dataset_names=all_names)

    print(f"{'Dataset Name':<35} {'Seeds':>6}  {'Harm Categories':<40} {'Description'}")
    print("-" * 130)

    for ds in sorted(datasets, key=lambda d: (d.dataset_name or d.name or "")):
        name = ds.dataset_name or ds.name or "unnamed"
        seed_count = len(ds.seeds)
        harm = ", ".join(ds.harm_categories) if ds.harm_categories else "-"
        description = (ds.description or "-")[:60]
        print(f"{name:<35} {seed_count:>6}  {harm:<40} {description}")

    print()


asyncio.run(main())
