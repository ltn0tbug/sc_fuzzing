from typing import Optional
from ollama import Client
from ollama import ResponseError


class OllamaClient:
    def __init__(
        self,
        model="llama3",
        base_url="http://localhost:11434",
    ):
        self.model = model
        self.client = Client(host=base_url.rstrip("/"))

    def submit(
        self,
        prompt: str,
        seed: Optional[int] = None,
        stream: bool = False,
        keep_alive: Optional[float | str] = -1,
        **extra_options,
    ) -> str:
        """
        Synchronous call with optional streaming using generate().
        - stream=False: returns full response string.
        - stream=True: prints tokens as they arrive, returns full text.
        """
        opts = {}
        if seed is not None:
            opts["options"] = {"seed": seed}
        if keep_alive is not None:
            opts["keep_alive"] = keep_alive
        opts.update(extra_options)

        # if opts.get("options") is None:
        #     opts["options"] = {}

        # opts["options"]['repeat_penalty'] = 1.0
        # opts["options"]['repeat_last_n'] = 0.0
        # opts["options"]['presence_penalty'] = 0.0
        # opts["options"]['frequency_penalty'] = 0.0

        try:
            if stream:
                return self._stream_and_collect(prompt, opts)
            else:
                resp = self.client.generate(
                    model=self.model, prompt=prompt, stream=False, **opts
                )
                return resp["response"]
        except ResponseError as e:
            raise RuntimeError(f"Ollama error: {e.error}") from e

    def _stream_and_collect(self, prompt: str, options) -> str:
        full = ""
        gen = self.client.generate(
            model=self.model, prompt=prompt, stream=True, **options
        )
        for part in gen:
            chunk = part.get("response", "")
            # print(chunk, end="", flush=True)
            full += chunk
        # print()
        return full
