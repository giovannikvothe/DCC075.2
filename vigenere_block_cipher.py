import struct

BLOCK_SIZE = 5
KEY_BYTES = [ord(c) for c in "035AC"]

def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def vigenere(block: bytes, encrypt: bool = True) -> bytes:
    op = 1 if encrypt else -1
    return bytes((b + op * k) % 256 for b, k in zip(block, KEY_BYTES))

def ecb(data: bytes, encrypt: bool = True) -> bytes:
    if encrypt:
        data = pad(data)
        result = b''.join(vigenere(data[i:i+BLOCK_SIZE], True) for i in range(0, len(data), BLOCK_SIZE))
    else:
        result = b''.join(vigenere(data[i:i+BLOCK_SIZE], False) for i in range(0, len(data), BLOCK_SIZE))
        result = unpad(result)
    return result

def cfb(data: bytes, iv: bytes, encrypt: bool = True) -> bytes:
    if encrypt:
        data = pad(data)
    
    sr = iv
    result = b''
    
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        encrypted_sr = vigenere(sr, True)
        processed = bytes((b ^ e) for b, e in zip(block, encrypted_sr))
        result += processed
        sr = processed if encrypt else block
    
    return unpad(result) if not encrypt else result

def header(mode: str, iv: bytes = None) -> bytes:
    h = b"VIGB" + bytes([1]) + mode.encode("ascii").ljust(3, b'\x00') + bytes([BLOCK_SIZE])
    if iv:
        h += iv
    return h + struct.pack(">I", 1)

if __name__ == "__main__":
    plaintext = b"CRIPTOGRAFIA"
    iv = b"INIT!"

    print(f"Chave: 035AC (bytes: {KEY_BYTES})")
    print(f"Texto original: {plaintext.decode()}")

    # Modo ECB
    c_ecb = ecb(plaintext, True)
    p_ecb = ecb(c_ecb, False)
    print(f"\n[ECB] Ciphertext: {c_ecb.hex(' ')}")
    print(f"[ECB] Decrypted: {p_ecb.decode()}")
    print(f"[ECB] Header: {header('ECB').hex(' ')}")

    # Modo CFB
    c_cfb = cfb(plaintext, iv, True)
    p_cfb = cfb(c_cfb, iv, False)
    print(f"\n[CFB] IV: {iv.decode()}")
    print(f"[CFB] Ciphertext: {c_cfb.hex(' ')}")
    print(f"[CFB] Decrypted: {p_cfb.decode()}")
    print(f"[CFB] Header: {header('CFB', iv).hex(' ')}")