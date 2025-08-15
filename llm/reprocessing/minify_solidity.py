import re


def remove_solidity_comments(code: str) -> str:
    result = []
    i = 0
    length = len(code)

    in_string = False
    string_char = ""
    in_triple_quote = False
    in_single_line_comment = False
    in_multi_line_comment = False

    while i < length:
        char = code[i]
        next_char = code[i + 1] if i + 1 < length else ""
        next_2 = code[i + 2] if i + 2 < length else ""

        # Detect triple-quoted strings (""")
        if not in_string and not in_single_line_comment and not in_multi_line_comment:
            if char == '"' and next_char == '"' and next_2 == '"':
                in_triple_quote = True
                in_string = True
                string_char = '"""'
                result.append('"""')
                i += 3
                continue

        # Start of a normal string
        if not in_string and not in_single_line_comment and not in_multi_line_comment:
            if char in ('"', "'"):
                in_string = True
                string_char = char
                result.append(char)
                i += 1
                continue

        # Inside string or triple-quoted string
        if in_string:
            result.append(char)
            if char == "\\":
                # Preserve escaped characters
                if i + 1 < length:
                    result.append(code[i + 1])
                    i += 2
                else:
                    i += 1
                continue

            # End of normal string
            if not in_triple_quote and char == string_char:
                in_string = False
                string_char = ""
                i += 1
                continue

            # End of triple-quoted string
            if in_triple_quote and char == '"' and next_char == '"' and next_2 == '"':
                result.append('""')
                in_string = False
                in_triple_quote = False
                string_char = ""
                i += 3
                continue

            i += 1
            continue

        # Start of single-line comment
        if (
            not in_single_line_comment
            and not in_multi_line_comment
            and char == "/"
            and next_char == "/"
        ):
            in_single_line_comment = True
            i += 2
            continue

        # Start of multi-line comment
        if (
            not in_single_line_comment
            and not in_multi_line_comment
            and char == "/"
            and next_char == "*"
        ):
            in_multi_line_comment = True
            i += 2
            continue

        # Inside single-line comment
        if in_single_line_comment:
            if char == "\n":
                in_single_line_comment = False
                result.append("\n")
            i += 1
            continue

        # Inside multi-line comment
        if in_multi_line_comment:
            if char == "*" and next_char == "/":
                in_multi_line_comment = False
                i += 2
            else:
                i += 1
            continue

        # Default case: not in string or comment
        result.append(char)
        i += 1

    # Optional warnings if comment or string was never closed
    if in_string:
        result.append("\n/* WARNING: Unterminated string literal */")
    elif in_multi_line_comment:
        result.append("\n/* WARNING: Unterminated multi-line comment */")

    return "".join(result)


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
    # Step 1: Remove single-line and multi-line comments
    code = remove_solidity_comments(code)

    # Step 2: Extract string literals
    code, string_literals = extract_strings(code)

    # Step 3: Normalize whitespace
    code = re.sub(r"\s+", " ", code)  # collapse all whitespace
    code = re.sub(r"\s*([{}();,=<>+\-*/&|!:])\s*", r"\1", code)  # tighten punctuation
    code = code.strip()

    # Step 4: Restore string literals
    code = restore_strings(code, string_literals)

    return code
