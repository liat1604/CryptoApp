import hashlib

 
# VIGENERE CIPHER
 
def vigenere_cipher(data: bytes, key: str, encrypt: bool = True) -> bytes:
    if not key:
        return data

    key_bytes = key.encode("utf-8")
    result = bytearray(len(data))

    for i in range(len(data)):
        k = key_bytes[i % len(key_bytes)]
        result[i] = (data[i] + k) % 256 if encrypt else (data[i] - k) % 256

    return bytes(result)


 
# VERNAM (XOR) CIPHER
 

def vernam_cipher(data: bytes, key: str) -> bytes:
    if not key:
        return data

    key_bytes = key.encode("utf-8")
    result = bytearray(len(data))

    for i in range(len(data)):
        result[i] = data[i] ^ key_bytes[i % len(key_bytes)]

    return bytes(result)


 
# COLUMNAR TRANSPOSITION
 
def columnar_transposition(data: bytes, key: str, encrypt: bool = True) -> bytes:
    if not key or len(key) < 2:
        return data
    cols = len(key)
    col_order = sorted(range(len(key)), key=lambda i: key[i])

    def pad_data(d, c):
        pad_len = (c - len(d) % c) % c
        return d + b"\x00" * pad_len

    if encrypt:
        header = len(data).to_bytes(8, "big")
        to_grid = header + data
        padded = pad_data(to_grid, cols)
        rows = len(padded) // cols

        result = bytearray()
        for c in col_order:
            for r in range(rows):
                result.append(padded[r * cols + c])
        return bytes(result)
    padded_len = len(data)

    if padded_len % cols != 0:
        raise ValueError("Invalid data length for Columnar decryption.")
    rows = padded_len // cols
    grid = bytearray(padded_len)

    idx = 0

    for c in col_order:
        for r in range(rows):
            grid[r * cols + c] = data[idx]
            idx += 1

    if len(grid) < 8:
        raise ValueError("Invalid data.")

    original_len = int.from_bytes(grid[:8], "big")

    return bytes(grid[8:8 + original_len])


 
# ORBIT CIPHER (Custom Multi‑Layer Cipher + Integrity Check)

def orbit_cipher_with_integrity(data: bytes, key: str, encrypt: bool = True) -> bytes:
    if not key:
        return data
    if encrypt:
        original_hash = hashlib.sha256(data).digest()
        combined = data + original_hash
        return orbit_cipher_core(combined, key, encrypt=True)
    else:
        decrypted = orbit_cipher_core(data, key, encrypt=False)
        if len(decrypted) < 32:
            raise ValueError("Invalid encrypted data (too short).")
        original = decrypted[:-32]
        stored = decrypted[-32:]
        if hashlib.sha256(original).digest() != stored:
            raise ValueError("Integrity check failed: wrong key or modified data.")
        return original
# ORBIT CIPHER — CORE LOGIC
def orbit_cipher_core(data: bytes, key: str, encrypt: bool) -> bytes:
    key_bytes = key.encode()
    expanded_key = _expand_key(key_bytes, 256)
    sbox = _generate_sbox(key_bytes)
    inv_sbox = _invert_sbox(sbox)
    result = bytearray(len(data))
    feedback = expanded_key[0]
    for i, byte in enumerate(data):
        key_byte = expanded_key[i % 256]
        rot = (key_byte + i) % 8
        if encrypt:
            mixed = byte ^ feedback ^ key_byte
            substituted = sbox[mixed]
            rotated = _rot_left(substituted, rot)
            out_b = (rotated + (i * key_byte)) % 256
            result[i] = out_b
            feedback = out_b ^ key_byte
        else:
            unshift = (byte - (i * key_byte)) % 256
            unrot = _rot_right(unshift, rot)
            unsub = inv_sbox[unrot]
            dec = unsub ^ feedback ^ key_byte
            result[i] = dec
            feedback = byte ^ key_byte
    return bytes(result)
# SUPPORT FUNCTIONS
def _expand_key(key_bytes: bytes, length: int) -> bytes:
    expanded = bytearray(length)
    klen = len(key_bytes)
    for i in range(length):
        expanded[i] = key_bytes[i % klen]
    for r in range(4):
        for i in range(length):
            prev = expanded[(i - 1) % length]
            expanded[i] = (expanded[i] + prev + r * 37) % 256
            expanded[i] ^= key_bytes[(i + r) % klen]
    return bytes(expanded)
def _generate_sbox(key_bytes: bytes) -> list:
    s = list(range(256))
    seed = sum(b * (i + 1) for i, b in enumerate(key_bytes)) % 256
    for i in range(255, 0, -1):
        seed = (seed * 1103515245 + 12345 + key_bytes[i % len(key_bytes)]) % (2**31)
        j = seed % (i + 1)
        s[i], s[j] = s[j], s[i]
    return s
def _invert_sbox(sbox: list) -> list:
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv
def _rot_left(b: int, n: int) -> int:
    n %= 8
    return ((b << n) & 0xFF) | (b >> (8 - n))
def _rot_right(b: int, n: int) -> int:
    n %= 8
    return (b >> n) | ((b << (8 - n)) & 0xFF)
