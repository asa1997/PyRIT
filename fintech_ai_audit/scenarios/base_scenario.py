from abc import ABC, abstractmethod
from typing import Optional
from pyrit.datasets import SeedDatasetProvider
from pyrit.prompt_target import PromptChatTarget, PromptTarget
from pyrit.score import Scorer, TrueFalseScorer

class BaseFintechScenario(ABC):
    """
    The abstract contract that EVERY threat scenario must strictly follow.
    This guarantees that our orchestrators (Attack and Batch Scoring) 
    can safely run any scenario without knowing its internal details.
    """
    
    # 1. Enforce that every scenario defines its metadata
    @property
    @abstractmethod
    def threat_name(self) -> str:
        pass

    @property
    @abstractmethod
    def owasp_mapping(self) -> str:
        pass

    @property
    @abstractmethod
    def mitre_atlas_mapping(self) -> str:
        pass

    @property
    @abstractmethod
    def dataset_names(self) -> list[str]:
        pass

    @staticmethod
    @abstractmethod
    def get_scorer(judge_llm: PromptChatTarget) -> TrueFalseScorer | Scorer:
        """
        Forces the scenario to explicitly define its own PyRIT Scorer.
        Used by batch_score.py for offline grading, or internally for live scoring.
        """
        pass
    
    @property
    @abstractmethod
    def attack_strategy(self) -> str:
        """
        Defines whether this scenario uses a single-turn attack
        or a multi-turn attack. This is used by the main orchestrator
        to know which AttackExecutor to use.
        """
        pass

    # =====================================================================
    # This automatically protects your 16GB RAM for every threat scenario.
    # =====================================================================
    async def execute(
        self,
        *,
        target_llm: PromptTarget,
        run_id: str,
        judge_llm: PromptChatTarget | None = None,
        max_prompts: int | None = None,
        **kwargs,
    ) -> None:
        """
        Fetches the datasets, slices them into hardware-safe chunks, labels them 
        for batch scoring, and passes them to the specific attack strategy.
        """
        # 1. Fetch datasets using the specific child class's requested datasets
        datasets = await SeedDatasetProvider.fetch_datasets_async(dataset_names=self.dataset_names)

        # 2. The Conveyor Belt Generator (Prevents 3 million prompts from crashing RAM)
        def get_prompt_chunks(datasets: list, chunk_size: int):
            chunk: list[str] = []
            processed_prompts = 0

            for dataset in datasets:
                for seed in dataset.seeds:
                    if max_prompts is not None and processed_prompts >= max_prompts:
                        break
                    
                    chunk.append(seed.value)
                    processed_prompts += 1

                    if len(chunk) == chunk_size:
                        yield chunk
                        chunk = []
                
                if max_prompts is not None and processed_prompts >= max_prompts:
                    break

            if chunk:
                yield chunk

        # 3. Safe Batching Loop
        CHUNK_SIZE = 5000 
        batch_num = 1
        
        if max_prompts is None:
            print(f"\n[*] Executing dataset: {self.dataset_names}")
        else:
            print(f"\n[*] Executing dataset: {self.dataset_names} (Limited to Capped {max_prompts} Prompts)")
        
        for current_chunk in get_prompt_chunks(datasets, CHUNK_SIZE):
            current_batch_id = f"batch_{batch_num}"
            
            print(f"  [+] Processing {current_batch_id} ({len(current_chunk)} prompts)...")
            
            # Inject the metadata and batch_id into PyRIT's memory for Phase 2
            labels = {
                "run_id": run_id,
                "threat": self.threat_name,
                "owasp": self.owasp_mapping,
                "mitre_atlas": self.mitre_atlas_mapping,
                "batch_id": current_batch_id,
                "dataset_names": self.dataset_names,
                "attack_strategy": self.attack_strategy,
            }

            # 4. HANDOFF: Pass this specific safe chunk to the child class's attack strategy
            await self._execute_attack_strategy(
                target_llm=target_llm,
                judge_llm=judge_llm,
                chunk=current_chunk,
                labels=labels
            )
            
            batch_num += 1

    # =====================================================================
    # Every specific threat file MUST define how it actually attacks the target.
    # =====================================================================
    
    @abstractmethod
    async def _execute_attack_strategy(self, target_llm: PromptTarget, judge_llm: Optional[PromptChatTarget], chunk: list[str], labels: dict):
        """
        Forces the scenario to define its specific single-turn or multi-turn attack logic.
        """
        pass
