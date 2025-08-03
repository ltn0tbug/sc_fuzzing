import json


def minify_json(json_input):
    """
    Minifies JSON string or Python object by removing all unnecessary whitespace.

    Args:
        json_input (str or dict): JSON string or parsed object.

    Returns:
        str: Minified JSON string.
    """
    if isinstance(json_input, str):
        # Parse the JSON string to object first
        data = json.loads(json_input)
    else:
        data = json_input

    # Dump as compact JSON (no spaces after commas/colons)
    return json.dumps(data, separators=(",", ":"))
