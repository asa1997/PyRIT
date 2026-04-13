from .insecure_code_generation import InsecureCodeScenario
from .prompt_injection import PromptInjectionScenario
from .prompt_injection_multiturn import PromptInjectionMultiTurnScenario

THREAT_REGISTRY = {
    "insecure_code_generation": InsecureCodeScenario,
    "prompt_injection": PromptInjectionScenario,
    "prompt_injection_multiturn": PromptInjectionMultiTurnScenario,
}
