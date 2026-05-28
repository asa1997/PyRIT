import asyncio
from pyrit.datasets import SeedDatasetProvider
from pyrit.memory import CentralMemory
from pyrit.setup.initialization import IN_MEMORY, initialize_pyrit_async


async def main():
    await SeedDatasetProvider.fetch_datasets_async()


if __name__ == "__main__":
    asyncio.run(main())