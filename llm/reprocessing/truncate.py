from transformers import AutoTokenizer


def get_token_length(text: str, model_name: str = "Qwen/Qwen2.5-Coder-7B") -> int:
    """
    Get the number of tokens in the input text for the specified model.

    Parameters:
        text (str): Input text to tokenize.
        model_name (str): Hugging Face model name for the tokenizer.

    Returns:
        int: Number of tokens in the text.
    """
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    encoded = tokenizer(text, return_tensors=None, add_special_tokens=False)
    return len(encoded["input_ids"])


def truncate_by_token_length(
    text: str,
    max_length: int,
    model_name: str = "Qwen/Qwen2.5-Coder-7B",
    from_head: bool = True,  # True = truncate from head (keep end), False = truncate from tail (keep start)
) -> tuple[str, int]:
    """
    Truncate input text by token length, optionally from the head.

    Parameters:
        text (str): The original input text.
        max_length (int): Maximum allowed tokens.
        model_name (str): Hugging Face model name for tokenizer.
        from_head (bool):
            - True: truncate from head (keep the end)
            - False: truncate from tail (keep the start)

    Returns:
        tuple[str, int]: (Truncated text, Number of tokens in truncated text)
    """
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    encoded = tokenizer(text, return_tensors=None, add_special_tokens=False)
    input_ids = encoded["input_ids"]

    if from_head:
        truncated_input_ids = input_ids[-max_length:]
    else:
        truncated_input_ids = input_ids[:max_length]

    truncated_text = tokenizer.decode(truncated_input_ids, skip_special_tokens=True)
    token_count = len(truncated_input_ids)

    return truncated_text, token_count
