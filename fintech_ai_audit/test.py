import asyncio
from pyrit.executor.attack import ConsoleAttackResultPrinter, PromptSendingAttack, AttackScoringConfig
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.datasets import SeedDatasetProvider
from pyrit.setup import SQLITE, initialize_pyrit_async
from pathlib import Path
from pyrit.score import SelfAskTrueFalseScorer

async def main():
    config_path = Path("/app/fintech_ai_audit/config.env")
    await initialize_pyrit_async(
                memory_db_type=SQLITE,
                env_files = [config_path]
                )
    datasets = await SeedDatasetProvider.fetch_datasets_async(dataset_names=["promptintel"])
    target = OpenAIChatTarget()
    true_false_classifier = SelfAskTrueFalseScorer(
    chat_target=OpenAIChatTarget(),
)

    attack = PromptSendingAttack(objective_target=target, attack_scoring_config=AttackScoringConfig(objective_scorer=true_false_classifier))
    result = await attack.execute_async(datasets)  # type: ignore

    printer = ConsoleAttackResultPrinter()
    await printer.print_conversation_async(result=result)  # type: ignore

asyncio.run(main())