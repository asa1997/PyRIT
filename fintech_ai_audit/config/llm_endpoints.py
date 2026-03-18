from pyrit.prompt_target import OpenAIChatTarget

def get_local_model(model_name: str):
    # Connects to local air-gapped Ollama instance
    return OpenAIChatTarget(model_name=model_name, max_requests_per_minute=60)
