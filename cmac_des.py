from des_single import compute_des_trace
import md5_algorithm   # your file


def cmac_des(message, n_bits):

    steps = []

    # ---------- STEP 1: CALL YOUR MD5 ----------
    md5_result = md5_algorithm.md5_hash_trace(message)

    full_hash = md5_result["hash"]   # ✅ IMPORTANT FIX
    steps.append(f"MD5 Hash (128-bit): {full_hash}")

    # ---------- STEP 2: TAKE FIRST 64 BITS ----------
    key_64 = full_hash[:16]
    steps.append(f"First 64 bits (Key): {key_64}")

    # ---------- STEP 3: ASCII CONVERSION ----------
    message_bytes = bytes([ord(c) for c in message])

    # ---------- STEP 4: PADDING ----------
    padding_len = 8 - (len(message_bytes) % 8)
    if padding_len != 8:
        message_bytes += b'\x00' * padding_len

    steps.append("Padded Message: " + message_bytes.hex())

    # ---------- STEP 5: DES CBC ----------
    result = compute_des_trace(
        plaintext=message_bytes.decode('latin-1'),
        key=key_64,
        mode='CBC',
        operation='ENCRYPT'
    )

    ciphertext = result['ciphertext']

    # ---------- STEP 6: BLOCKS ----------
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    steps.append("Encrypted Blocks:")
    for i, b in enumerate(blocks):
        steps.append(f"C{i+1} = {b}")

    # ---------- STEP 7: LAST BLOCK ----------
    last_block = blocks[-1]
    steps.append(f"Last Block = {last_block}")

    # ---------- STEP 8: BINARY ----------
    binary = bin(int(last_block, 16))[2:].zfill(64)
    steps.append(f"Binary = {binary}")

    # ---------- STEP 9: TRUNCATE ----------
    truncated = binary[:n_bits]
    steps.append(f"First {n_bits} bits = {truncated}")

    # ---------- STEP 10: FINAL CMAC ----------
    cmac_val = hex(int(truncated, 2))[2:]
    steps.append(f"CMAC = {cmac_val}")

    return {
        "cmac": cmac_val,
        "steps": steps
    }
