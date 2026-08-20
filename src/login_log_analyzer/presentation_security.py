import unicodedata


CSV_FORMULA_PREFIXES = frozenset("=+-@")
UNSAFE_UNICODE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def escape_control_characters(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("value must be a string")

    escaped: list[str] = []
    for character in value:
        if unicodedata.category(character) not in UNSAFE_UNICODE_CATEGORIES:
            escaped.append(character)
            continue
        code_point = ord(character)
        if code_point <= 0xFF:
            escaped.append(f"\\x{code_point:02x}")
        elif code_point <= 0xFFFF:
            escaped.append(f"\\u{code_point:04x}")
        else:
            escaped.append(f"\\U{code_point:08x}")
    return "".join(escaped)


def neutralize_csv_text(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("value must be a string")

    significant_value = value.lstrip(" \t\r\n")
    needs_formula_prefix = (
        bool(significant_value)
        and significant_value[0] in CSV_FORMULA_PREFIXES
    ) or value.startswith(("\t", "\r", "\n"))
    escaped_value = escape_control_characters(value)
    return f"'{escaped_value}" if needs_formula_prefix else escaped_value
