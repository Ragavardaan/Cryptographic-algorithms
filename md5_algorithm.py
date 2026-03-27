import struct
import math


def leftrotate(x, c):
    x = x & 0xffffffff
    return ((x << c) | (x >> (32 - c))) & 0xffffffff


def md5_hash_trace(message):

    steps = []

    # ---------- Safety ----------
    if not isinstance(message, str):
        message = str(message)

    # ---------- Padding ----------
    msg_bytes = message.encode()
    original_length = len(msg_bytes) * 8

    msg_bytes += b'\x80'

    while (len(msg_bytes) * 8) % 512 != 448:
        msg_bytes += b'\x00'

    msg_bytes += struct.pack('<Q', original_length)

    steps.append(f"Total message size after padding = {len(msg_bytes)*8} bits")

    steps.append("Padded Message (hex):")
    steps.append(msg_bytes.hex())

    # ---------- Initial Buffers ----------
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    steps.append("Initial Buffers:")
    steps.append(f"A = 0x{A:08x}")
    steps.append(f"B = 0x{B:08x}")
    steps.append(f"C = 0x{C:08x}")
    steps.append(f"D = 0x{D:08x}")

    # ---------- Constants ----------
    s = [
        7,12,17,22]*4 + \
        [5,9,14,20]*4 + \
        [4,11,16,23]*4 + \
        [6,10,15,21]*4

    K = [int(abs(math.sin(i+1)) * (2**32)) & 0xffffffff for i in range(64)]

    # ---------- Process ----------
    for chunk in range(0, len(msg_bytes), 64):

        M = list(struct.unpack('<16I', msg_bytes[chunk:chunk+64]))

        steps.append("M values (32-bit words):")
        for i in range(16):
            steps.append(f"M[{i:2}] = 0x{M[i]:08x}")

        a, b, c, d = A, B, C, D

        # ---------- 64 Iterations ----------
        for i in range(64):

            if i < 16:
                func = ((b & c) | ((~b) & d)) & 0xffffffff
                g = i
                round_name = "Round 1"
            elif i < 32:
                func = ((b & d) | (c & (~d))) & 0xffffffff
                g = (5*i + 1) % 16
                round_name = "Round 2"
            elif i < 48:
                func = (b ^ c ^ d) & 0xffffffff
                g = (3*i + 5) % 16
                round_name = "Round 3"
            else:
                func = (c ^ (b | (~d))) & 0xffffffff
                g = (7*i) % 16
                round_name = "Round 4"

            temp = (a + func + K[i] + M[g]) & 0xffffffff
            temp = leftrotate(temp, s[i])
            temp = (b + temp) & 0xffffffff

            a, d, c, b = d, c, b, temp

            steps.append(
                f"{round_name} Step {i%16 + 1:2}: "
                f"A=0x{a:08x} B=0x{b:08x} C=0x{c:08x} D=0x{d:08x}"
            )

        # ---------- Add to main buffers ----------
        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff

    # ---------- Final Hash ----------
    digest = struct.pack('<4I', A, B, C, D).hex()

    steps.append("Final MD5 Hash:")
    steps.append(digest)

    return {
        "hash": digest,
        "steps": steps
    }
