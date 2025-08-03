import re


def extract_strings(code):
    """
    Extract both single-quoted and double-quoted string literals.
    Replace them with placeholders.
    """
    strings = []

    def replacer(match):
        strings.append(match.group(0))
        return f"__STRING_{len(strings) - 1}__"

    # Matches both '...' and "..." strings, handling escape sequences
    string_regex = r"""("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
    code = re.sub(string_regex, replacer, code)
    return code, strings


def restore_strings(code, strings):
    """
    Replace string placeholders with original string literals.
    """
    for i, s in enumerate(strings):
        code = code.replace(f"__STRING_{i}__", s)
    return code


def minify_solidity(code):
    # Step 1: Extract string literals
    code, string_literals = extract_strings(code)

    # Step 2: Remove single-line and multi-line comments
    code = re.sub(r"//.*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)

    # Step 3: Normalize whitespace
    code = re.sub(r"\s+", " ", code)  # collapse all whitespace
    code = re.sub(r"\s*([{}();,=<>+\-*/&|!:])\s*", r"\1", code)  # tighten punctuation
    code = code.strip()

    # Step 4: Restore string literals
    code = restore_strings(code, string_literals)

    return code
