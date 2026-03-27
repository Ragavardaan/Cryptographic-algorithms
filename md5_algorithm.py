import struct
import math

def leftrotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xffffffff


def md5_hash_trace(message):

    steps = []
    rounds = [[], [], [], []]   # 4 round boxes

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
    steps.append(f"A = {hex(A)}")
    steps.append(f"B = {hex(B)}")
    steps.append(f"C = {hex(C)}")
    steps.append(f"D = {hex(D)}")

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
            steps.append(f"M[{i}] = {hex(M[i])}")

        a, b, c, d = A, B, C, D

        for i in range(64):

            if i < 16:
                func = (b & c) | (~b & d)
                g = i
                r = 0
            elif i < 32:
                func = (b & d) | (c & ~d)
                g = (5*i + 1) % 16
                r = 1
            elif i < 48:
                func = b ^ c ^ d
                g = (3*i + 5) % 16
                r = 2
            else:
                func = c ^ (b | ~d)
                g = (7*i) % 16
                r = 3

            temp = (a + func + K[i] + M[g]) & 0xffffffff
            temp = leftrotate(temp, s[i])
            temp = (b + temp) & 0xffffffff

            a, d, c, b = d, c, b, temp

            rounds[r].append(
                f"Step {i%16 + 1}: A={hex(a)} B={hex(b)} C={hex(c)} D={hex(d)}"
            )

        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff

    digest = struct.pack('<4I', A, B, C, D).hex()

    return {
        "hash": digest,
        "steps": steps,
        "rounds": rounds
    }
