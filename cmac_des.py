from DES import compute_des_trace


def cmac_des(message, key, n_bits):

    steps = []

    # ---------- Padding ----------
    if isinstance(message, str):
        message = message.encode()

    padding_len = 8 - (len(message) % 8)
    if padding_len != 8:
        message += b'\x00' * padding_len

    steps.append("Padded Message (hex): " + message.hex())

    # ---------- DES CBC ----------
    result = compute_des_trace(
        plaintext=message.hex(),
        key=key,
        mode='CBC',
        operation='ENCRYPT'
    )

    ciphertext = result['ciphertext']

    # ---------- Split blocks ----------
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    steps.append("Encrypted Blocks:")
    for i, b in enumerate(blocks):
        steps.append(f"C{i+1} = {b}")

    # ---------- Last block ----------
    last_block = blocks[-1]
    steps.append(f"Last Block = {last_block}")

    # ---------- Convert to binary ----------
    binary = bin(int(last_block, 16))[2:].zfill(64)
    steps.append(f"Binary (64-bit) = {binary}")

    # ---------- Take first n bits ----------
    truncated = binary[:n_bits]
    steps.append(f"First {n_bits} bits = {truncated}")

    # ---------- Convert to hex ----------
    hex_val = hex(int(truncated, 2))[2:]
    steps.append(f"CMAC ({n_bits}-bit) = {hex_val}")

    return {
        "cmac": hex_val,
        "steps": steps
    }
