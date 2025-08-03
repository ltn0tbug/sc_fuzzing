from transformers import AutoTokenizer


def truncate_by_token_length(
    text: str, max_length: int, model_name: str = "Qwen/Qwen2.5-Coder-7B"
) -> tuple[str, int]:
    """
    Truncate input text to fit within max_length tokens using the specified tokenizer.

    Parameters:
        text (str): The original input text.
        max_length (int): Maximum allowed tokens.
        model_name (str): Hugging Face model name for tokenizer.

    Returns:
        tuple[str, int]: (Truncated text, Number of tokens in truncated text)
    """
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    # Encode and truncate
    encoded = tokenizer(
        text, truncation=True, max_length=max_length, return_tensors=None
    )

    # Decode back to text
    truncated_text = tokenizer.decode(encoded["input_ids"], skip_special_tokens=True)
    token_count = len(encoded["input_ids"])

    return truncated_text, token_count
