import struct
import math

# --------- 1) Left rotate (32-bit) ----------
def leftrotate(x, c):
    x &= 0xffffffff
    return ((x << c) | (x >> (32 - c))) & 0xffffffff


# --------- 2) Padding + length append (with trace) ----------
def md5_pad_trace(msg_bytes, steps):
    original_length = len(msg_bytes) * 8
    steps.append(f"Original message length = {original_length} bits")
    # append 1 bit (as 0x80), then 0x00 until length ≡ 448 (mod 512)
    msg_bytes += b"\x80"
    while (len(msg_bytes) * 8) % 512 != 448:
        msg_bytes += b"\x00"

    # append length as 64-bit little-endian
    msg_bytes += struct.pack("<Q", original_length)

    steps.append("Padding completed (message length ≡ 448 mod 512)")
    steps.append("64-bit length appended")
    return msg_bytes


# --------- 3) MD5 f-calculation + g index ----------
def md5_f_and_g(i, b, c, d):
    if i < 16:
        func = (b & c) | (~b & d)
        g = i
    elif i < 32:
        func = (b & d) | (c & ~d)
        g = (5 * i + 1) % 16
    elif i < 48:
        func = b ^ c ^ d
        g = (3 * i + 5) % 16
    else:
        func = c ^ (b | ~d)
        g = (7 * i) % 16

    return func & 0xffffffff, g


# --------- 4) MD5 main algorithm with trace output ----------
def md5_hash_trace(message):
    steps = []

    # ---------- ASCII / bytes ----------
    steps.append("ASCII Conversion:")
    msg_bytes = message.encode("utf-8")

    for ch in message:
        steps.append(f"{ch} = {ord(ch)}")

    # ---------- Padding ----------
    msg_bytes = md5_pad_trace(msg_bytes, steps)

    # ---------- Initial Buffers ----------
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    steps.append("Initial MD5 Buffers:")
    steps.append(f"A = {hex(A)}")
    steps.append(f"B = {hex(B)}")
    steps.append(f"C = {hex(C)}")
    steps.append(f"D = {hex(D)}")

    # ---------- Rotation constants ----------
    s = (
        [7, 12, 17, 22] * 4 +
        [5, 9, 14, 20] * 4 +
        [4, 11, 16, 23] * 4 +
        [6, 10, 15, 21] * 4
    )

    # ---------- K constants ----------
    K = [int(abs(math.sin(i + 1)) * (2**32)) & 0xffffffff for i in range(64)]

    # ---------- Process 512-bit Blocks ----------
    for chunk in range(0, len(msg_bytes), 64):
        # sixteen 32-bit little-endian words
        W = list(struct.unpack("<16I", msg_bytes[chunk:chunk + 64]))

        a, b, c, d = A, B, C, D

        for i in range(64):
            func, g = md5_f_and_g(i, b, c, d)

            temp = (a + func + K[i] + W[g]) & 0xffffffff
            temp = leftrotate(temp, s[i])
            temp = (b + temp) & 0xffffffff

            a, d, c, b = d, c, b, temp

        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff

    steps.append("All 64 MD5 operations completed")

    digest = struct.pack("<4I", A, B, C, D).hex()
    steps.append(f"Final MD5 Hash = {digest}")

    return {"hash": digest, "steps": steps}