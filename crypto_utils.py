# crypto_utils.py

def char_to_index(ch):
    if not isinstance(ch, str) or len(ch) != 1: return -1
    code = ord(ch.lower())
    return code - 97 if 97 <= code <= 122 else -1

def index_to_lower_char(index):
    return chr(97 + ((index % 26) + 26) % 26)

def index_to_upper_char(index):
    return chr(65 + ((index % 26) + 26) % 26)