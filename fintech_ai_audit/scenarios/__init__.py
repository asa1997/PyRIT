from .insecure_code_generation import InsecureCodeScenario
from .prompt_injection import PromptInjectionScenario
from .red_teaming_multiturn import RedTeamingMultiTurnScenario

THREAT_REGISTRY = {
    "insecure_code_generation": InsecureCodeScenario,
    "prompt_injection": PromptInjectionScenario,
    "red_teaming_multiturn": RedTeamingMultiTurnScenario,
}
