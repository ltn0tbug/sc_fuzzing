from .openai_client import OpenAIClient
from .ollama_client import OllamaClient

SUPPORTED_PROVIDER = ["ollama", "openai"]


class PromptSubmitter:
    def __init__(
        self,
        provider="ollama",
        model="llama3",
        ollama_base_url="http://localhost:11434/",
    ):
        if provider.lower() not in SUPPORTED_PROVIDER:
            raise ValueError(
                f"Unsupported provider: {provider}. Supported providers are: {SUPPORTED_PROVIDER}"
            )

        self.provider = provider.lower()
        self.model = model
        self.ollama_base_url = ollama_base_url

        if self.provider == "openai":
            self.client = OpenAIClient(model=self.model)
        elif self.provider == "ollama":
            self.client = OllamaClient(model=self.model, base_url=self.ollama_base_url)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def submit(self, prompt_text, *arg, **kwargs):
        return self.client.submit(prompt_text, *arg, **kwargs)
