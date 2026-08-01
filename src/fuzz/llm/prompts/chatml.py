"""ChatML wrapper template used by the llama-cpp backend.

llama-cpp's /completion endpoint takes raw text; we wrap (system, user) into
the ChatML format used by Qwen, Mistral, and most chat-tuned models. The
"<|im_end|>" stop token tells the server to stop sampling cleanly at end-of-
turn (belt-and-suspenders alongside the GBNF root closing the JSON array).
"""

CHATML_TEMPLATE = (
    "<|im_start|>system\n{system}<|im_end|>\n"
    "<|im_start|>user\n{user}<|im_end|>\n"
    "<|im_start|>assistant\n"
)
