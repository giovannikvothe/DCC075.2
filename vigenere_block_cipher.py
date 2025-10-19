import struct

BLOCK_SIZE = 5
key_string = "035AC"
KEY_BYTES = []
for char in key_string:
    byte_value = ord(char)
    KEY_BYTES.append(byte_value)

def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]

def vigenere(block: bytes, encrypt: bool = True) -> bytes:
    if encrypt:
        op = 1
    else:
        op = -1
    
    result = []
    for i in range(len(block)):
        b = block[i]
        k = KEY_BYTES[i]
        new_byte = (b + op * k) % 256
        result.append(new_byte)
    
    return bytes(result)

def ecb(data: bytes, encrypt: bool = True) -> bytes:
    if encrypt:
        data = pad(data)
        
        result = b''
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            encrypted_block = vigenere(block, True)
            result = result + encrypted_block
    else:
        result = b''
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            decrypted_block = vigenere(block, False)
            result = result + decrypted_block
        
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
        processed = []
        for j in range(len(block)):
            b = block[j]
            e = encrypted_sr[j]
            xor_result = b ^ e
            processed.append(xor_result)
        processed = bytes(processed)
        result += processed
        sr = processed if encrypt else block
    
    return unpad(result) if not encrypt else result

def header(mode: str, iv: bytes = None) -> bytes:
    magic = b"VIGB"
    version = bytes([1])
    mode_bytes = mode.encode("ascii")
    mode_padded = mode_bytes.ljust(3, b'\x00')
    block_size_bytes = bytes([BLOCK_SIZE])
    
    h = magic + version + mode_padded + block_size_bytes
    
    if iv:
        h = h + iv
    
    length_bytes = struct.pack(">I", 1)
    h = h + length_bytes
    
    return h

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