from .insecure_code_generation import InsecureCodeScenario
from .prompt_injection import PromptInjectionScenario

THREAT_REGISTRY = {
    "insecure_code_generation": InsecureCodeScenario,
    "prompt_injection": PromptInjectionScenario,
}
