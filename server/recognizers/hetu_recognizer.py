"""
Finnish Personal Identity Code (Henkilötunnus / HETU) validator and recognizer for Python.
"""

from datetime import datetime
import re

HETU_CHECKSUM_CHARS = "0123456789ABCDEFHJKLMNPRSTUVWXY"

def validate_finnish_hetu(hetu: str) -> bool:
    if not hetu or len(hetu) != 11:
        return False

    pattern = r"^(\d{2})(\d{2})(\d{2})([+\-A-Fa-fU-Yu-y])(\d{3})([0-9A-Za-z])$"
    match = re.match(pattern, hetu)
    if not match:
        return False

    day = int(match.group(1))
    month = int(match.group(2))
    year_short = int(match.group(3))
    sep = match.group(4).upper()
    checksum_char = match.group(6).upper()

    if day < 1 or day > 31 or month < 1 or month > 12:
        return False

    if sep == "+":
        full_year = 1800 + year_short
    elif sep == "-":
        full_year = 1900 + year_short
    elif sep in "ABCDEFUWXYZ":
        full_year = 2000 + year_short
    else:
        return False

    try:
        datetime(full_year, month, day)
    except ValueError:
        return False

    num_str = f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(5)}"
    num_to_divide = int(num_str)
    remainder = num_to_divide % 31
    expected_char = HETU_CHECKSUM_CHARS[remainder]

    return checksum_char == expected_char


def find_finnish_hetus(text: str):
    hetu_regex = re.compile(r"\b\d{6}[+\-A-Fa-fU-Yu-y]\d{3}[0-9A-Za-z]\b")
    results = []
    for match in hetu_regex.finditer(text):
        token = match.group(0)
        if validate_finnish_hetu(token):
            results.append({
                "hetu": token,
                "start": match.start(),
                "end": match.end()
            })
    return results

