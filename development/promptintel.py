import asyncio

from pyrit.datasets.seed_datasets.remote import _PromptIntelDataset

from pyrit.datasets import SeedDatasetProvider

async def main():
    seed_dataset = await SeedDatasetProvider.fetch_datasets_async(dataset_names=["promptintel"])
    # for dataset in dataset:
    #     for seed in dataset.seeds[:3]:
    #         print(f"harm_categories: {seed.harm_categories}")
    #         print(f"metadata: {seed.metadata}")
    #         print()
    # # dataset_loader = _PromptIntelDataset()
    # seed_dataset = await dataset_loader.fetch_dataset()

    target_categories = [
        "Direct prompt injection",
        "Indirect prompt injection",
        "Exploit or payload output",
    ]

    for category in target_categories:
        print(f"\n=== {category} ===")
        count = 0
        for dataset in seed_dataset:
            for seed in dataset.seeds:
                if seed.harm_categories and category in seed.harm_categories:
                    print(f"\n  [{count + 1}] {seed.value[:200]}")
                    count += 1
                    if count >= 2:
                        break
            if count >= 2:
                break
        if count == 0:
            print("  (no prompts found)")


if __name__ == "__main__":
    asyncio.run(main())
