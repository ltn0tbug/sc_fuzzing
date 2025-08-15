import re
from .dataloader import DataLoader
import fasttext
from pathlib import Path


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


def split_identifier(identifier):
    # Split CamelCase and snake_case: e.g., safeTransferFrom → safe, transfer, from
    parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", identifier)
    snake_split = []
    for part in parts:
        snake_split += part.lower().split("_")
    return [p for p in snake_split if p]


def tokenize_code(code):
    # Regex patterns for Solidity tokens
    token_pattern = re.compile(
        r"""
        (0x[a-fA-F0-9]+)             | # Hex numbers
        (\d+\.\d+|\d+)               | # Numbers
        ("[^"]*"|'[^']*')            | # Strings
        (\b[_A-Za-z][_A-Za-z0-9]*\b) | # Identifiers
        ([{}()\[\];,.<>!=+\-*/&|^~%])  # Symbols
    """,
        re.VERBOSE,
    )

    tokens = []
    for match in token_pattern.finditer(code):
        token = match.group(0)

        if match.group(4):  # identifier
            tokens.extend(split_identifier(token))
        elif match.group(1) or match.group(2) or match.group(3):
            continue  # Skip literals (optional)
        else:
            tokens.append(token)

    return " ".join(tokens)


def build_fasttext_corpus(file_list, output_path):
    with open(output_path, "w", encoding="utf-8") as out_f:
        for path in file_list:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()
                    code = remove_solidity_comments(code)
                    tokens = tokenize_code(code)
                    out_f.write(tokens + "\n")  # One line per file
            except Exception as e:
                print(f"Error processing {path}: {e}")


def create_fasttext_w2v(force=True):
    if not force and Path("solidity_fasttext_model.bin").exists():
        return
    sol_file_template = r"{}/contracts/{}.sol"
    sol_list = []
    for _, s in DataLoader().get_metadata("smartbugs_curated").iterrows():
        sol_list.append(sol_file_template.format(s["project_path"], s["name"]))
    for _, s in DataLoader().get_metadata("smartbugs_wild").iterrows():
        sol_list.append(sol_file_template.format(s["project_path"], s["name"]))

    build_fasttext_corpus(sol_list, "solidity_corpus.txt")
    model = fasttext.train_unsupervised(
        "solidity_corpus.txt", model="skipgram", dim=300
    )
    model.save_model("solidity_fasttext_model.bin")
