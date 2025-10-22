#Nomes:
#Guilherme Roldão dos Reis Pimenta - 202435001
#Giovanni Almeida Dutra - 202465035AC

import struct

BLOCK_SIZE = 5
key_string = "035AC"
KEY_BYTES = []
for char in key_string:
    byte_value = ord(char)
    KEY_BYTES.append(byte_value)

def pad(data: bytes) -> bytes:
    """
    Padding PKCS#7 modificado:
    - Calcula quantos bytes faltam para completar um bloco
    - Adiciona bytes com o valor do tamanho do padding
    """
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """
    Remove padding PKCS#7:
    - Lê o último byte para saber quantos bytes de padding remover
    - Retorna os dados sem o padding
    """
    return data[:-data[-1]]

def vigenere(block: bytes, encrypt: bool = True) -> bytes:
    """
    Cifra de Vigenère modificada para bytes:
    - Criptografia: byte + chave (mod 256)
    - Descriptografia: byte - chave (mod 256)
    """
    if encrypt:
        op = 1  # Adição para criptografia
    else:
        op = -1  # Subtração para descriptografia
    
    result = []
    for i in range(len(block)):
        b = block[i]  # Byte do bloco
        k = KEY_BYTES[i]  # Byte da chave
        new_byte = (b + op * k) % 256  # Operação modular
        result.append(new_byte)
    
    return bytes(result)

def ecb(data: bytes, encrypt: bool = True) -> bytes:
    """
    Modo ECB (Electronic Codebook) - cada bloco é criptografado independentemente
    """
    if encrypt:
        # Criptografia: adiciona padding e processa cada bloco independentemente
        data = pad(data)
        
        result = b''
        for i in range(0, len(data), BLOCK_SIZE):
            # Aplica vigenere no bloco e concatena ao resultado
            block = data[i:i+BLOCK_SIZE]
            encrypted_block = vigenere(block, True)
            result = result + encrypted_block
    else:
        # Descriptografia: processa cada bloco e remove padding
        result = b''
        for i in range(0, len(data), BLOCK_SIZE):
            # Aplica a descriptografia de vigenere no bloco e concatena ao resultado
            block = data[i:i+BLOCK_SIZE]
            decrypted_block = vigenere(block, False)
            result = result + decrypted_block
        
        result = unpad(result)
    
    return result

def cfb(data: bytes, iv: bytes, encrypt: bool = True) -> bytes:
    """
    Modo CFB (Cipher Feedback) - usa feedback do ciphertext para criptografar próximo bloco
    """
    if encrypt:
        # Criptografia: processa da esquerda para direita
        sr = iv  # Shift Register inicia com IV
        result = b''
        
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            encrypted_sr = vigenere(sr, True)  # Criptografa SR com Vigenère
            processed = []
            for j in range(len(block)):
                b = block[j]
                e = encrypted_sr[j]
                xor_result = b ^ e  # XOR entre plaintext e SR criptografado
                processed.append(xor_result)
            processed = bytes(processed)
            result += processed
            sr = processed  # SR = resultado da operação XOR
        
        return result
    else:
        # Descriptografia: processa da esquerda para direita (ordem normal)
        sr = iv  # Shift Register inicia com IV
        result = b''
        
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            encrypted_sr = vigenere(sr, True)  # Criptografa SR com Vigenère
            processed = []
            for j in range(len(block)):
                b = block[j]
                e = encrypted_sr[j]
                xor_result = b ^ e  # XOR entre ciphertext e SR criptografado
                processed.append(xor_result)
            processed = bytes(processed)
            result += processed
            sr = block  # SR = bloco do ciphertext original
        
        return result

def header(mode: str, plaintext: bytes, iv: bytes = None) -> bytes:
    """
    Cria header do arquivo cifrado:
    - Magic: "VIGB" (4 bytes)
    - Version: 1 (1 byte)
    - Mode: ECB/CFB (3 bytes, padded)
    - Block size: tamanho do bloco (1 byte)
    - IV: vetor de inicialização (se CFB)
    - Length: tamanho dos dados (4 bytes)
    """
    magic = b"VIGB"  # Identificador do formato
    version = bytes([1])  # Versão do formato
    mode_bytes = mode.encode("ascii")
    mode_padded = mode_bytes.ljust(3, b'\x00')  # Padding para 3 bytes
    block_size_bytes = bytes([BLOCK_SIZE])
    
    h = magic + version + mode_padded + block_size_bytes
    
    if iv:  # Adiciona IV se modo CFB
        h = h + iv
    
    length = len(plaintext)
    length_bytes = struct.pack(">I", length)
    h = h + length_bytes
    
    return h

def passo_a_passo_vigenere(block: bytes, encrypt: bool = True) -> bytes:
    print(f"\n=== PASSO A PASSO VIGENÈRE ({'CRIPTOGRAFIA' if encrypt else 'DESCRIPTOGRAFIA'}) ===")
    print(f"Bloco de entrada: {block.hex(' ')} ({len(block)} bytes)")
    print(f"Chave: {KEY_BYTES}")
    
    if encrypt:
        op = 1
        print("Operação: CRIPTOGRAFIA (adição)")
    else:
        op = -1
        print("Operação: DESCRIPTOGRAFIA (subtração)")
    
    result = []
    for i in range(len(block)):
        b = block[i]
        k = KEY_BYTES[i]
        if encrypt:
            new_byte = (b + k) % 256
            print(f"  Byte {i}: {b:3d} + {k:3d} = {new_byte:3d} (mod 256)")
        else:
            new_byte = (b - k) % 256
            print(f"  Byte {i}: {b:3d} - {k:3d} = {new_byte:3d} (mod 256)")
        result.append(new_byte)
    
    resultado_bytes = bytes(result)
    print(f"Resultado: {resultado_bytes.hex(' ')}")
    return resultado_bytes

def passo_a_passo_padding(data: bytes, operacao: str) -> bytes:
    print(f"\n=== PASSO A PASSO PADDING ({operacao}) ===")
    print(f"Dados originais: {data.hex(' ')} ({len(data)} bytes)")
    
    if operacao == "ADICIONAR":
        pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        print(f"Tamanho do bloco: {BLOCK_SIZE}")
        print(f"Bytes restantes: {len(data) % BLOCK_SIZE}")
        print(f"Bytes de padding necessários: {pad_len}")
        
        padded_data = data + bytes([pad_len] * pad_len)
        print(f"Dados com padding: {padded_data.hex(' ')}")
        print(f"Padding adicionado: {bytes([pad_len] * pad_len).hex(' ')}")
        return padded_data
    
    else:  # REMOVER
        pad_len = data[-1]
        print(f"Último byte indica padding: {pad_len}")
        print(f"Padding a remover: {data[-pad_len:].hex(' ')}")
        
        unpadded_data = data[:-pad_len]
        print(f"Dados sem padding: {unpadded_data.hex(' ')}")
        return unpadded_data

def passo_a_passo_ecb(data: bytes, encrypt: bool = True) -> bytes:
    print(f"\n{'='*60}")
    print(f"PASSO A PASSO ECB - {'CRIPTOGRAFIA' if encrypt else 'DESCRIPTOGRAFIA'}")
    print(f"{'='*60}")
    
    if encrypt:
        print(f"Texto original: {data.decode()}")
        print(f"Texto em bytes: {data.hex(' ')}")
        
        # Passo 1: Padding
        padded_data = passo_a_passo_padding(data, "ADICIONAR")
        
        # Passo 2: Divisão em blocos
        print(f"\n=== DIVISÃO EM BLOCOS ===")
        print(f"Dados com padding: {padded_data.hex(' ')} ({len(padded_data)} bytes)")
        print(f"Tamanho do bloco: {BLOCK_SIZE}")
        
        result = b''
        for i in range(0, len(padded_data), BLOCK_SIZE):
            block = padded_data[i:i+BLOCK_SIZE]
            print(f"\n--- Bloco {i//BLOCK_SIZE + 1} ---")
            print(f"Posição: {i} a {i+BLOCK_SIZE-1}")
            print(f"Bloco: {block.hex(' ')}")
            
            encrypted_block = passo_a_passo_vigenere(block, True)
            result = result + encrypted_block
            
        print(f"\n=== RESULTADO FINAL ECB ===")
        print(f"Ciphertext completo: {result.hex(' ')}")
        return result
    
    else:
        print(f"Ciphertext: {data.hex(' ')}")
        
        # Passo 1: Divisão em blocos
        print(f"\n=== DIVISÃO EM BLOCOS ===")
        print(f"Ciphertext: {data.hex(' ')} ({len(data)} bytes)")
        print(f"Tamanho do bloco: {BLOCK_SIZE}")
        
        result = b''
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            print(f"\n--- Bloco {i//BLOCK_SIZE + 1} ---")
            print(f"Posição: {i} a {i+BLOCK_SIZE-1}")
            print(f"Bloco: {block.hex(' ')}")
            
            decrypted_block = passo_a_passo_vigenere(block, False)
            result = result + decrypted_block
            
        # Passo 2: Remover padding
        unpadded_result = passo_a_passo_padding(result, "REMOVER")
        
        print(f"\n=== RESULTADO FINAL ECB ===")
        print(f"Texto descriptografado: {unpadded_result.decode()}")
        return unpadded_result

def passo_a_passo_cfb(data: bytes, iv: bytes, encrypt: bool = True) -> bytes:
    print(f"\n{'='*60}")
    print(f"PASSO A PASSO CFB - {'CRIPTOGRAFIA' if encrypt else 'DESCRIPTOGRAFIA'}")
    print(f"{'='*60}")
    
    if encrypt:
        print(f"Texto original: {data.decode()}")
        print(f"Texto em bytes: {data.hex(' ')}")
        print(f"IV: {iv.decode()} ({iv.hex(' ')})")
        
        
    else:
        print(f"Ciphertext: {data.hex(' ')}")
        print(f"IV: {iv.decode()} ({iv.hex(' ')})")
    
    # Passo 1: Processamento CFB
    print(f"\n=== PROCESSAMENTO CFB ===")
    print(f"Dados para processar: {data.hex(' ')} ({len(data)} bytes)")
    
    if encrypt:
        print(f"NOTA: CFB criptografia processa da esquerda para direita")
        print(f"SR atualiza com resultado XOR a cada iteração")
        
        sr = iv
        result = b''
        
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            print(f"\n--- Iteração {i//BLOCK_SIZE + 1} ---")
            print(f"Bloco atual: {block.hex(' ')}")
            print(f"Shift Register (SR): {sr.hex(' ')}")
            
            print(f"\n1. Criptografando SR com Vigenère:")
            encrypted_sr = passo_a_passo_vigenere(sr, True)
            
            print(f"\n2. Operação XOR:")
            processed = []
            for j in range(len(block)):
                b = block[j]
                e = encrypted_sr[j]
                xor_result = b ^ e
                print(f"   Byte {j}: {b:3d} ^ {e:3d} = {xor_result:3d}")
                processed.append(xor_result)
            processed = bytes(processed)
            print(f"   Resultado XOR: {processed.hex(' ')}")
            
            result += processed
            sr = processed
            print(f"3. Novo SR (resultado XOR): {sr.hex(' ')}")
    else:
        print(f"NOTA: CFB descriptografia processa da esquerda para direita")
        print(f"SR atualiza com bloco ciphertext a cada iteração")
        
        sr = iv
        result = b''
        
        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            print(f"\n--- Iteração {i//BLOCK_SIZE + 1} ---")
            print(f"Bloco atual: {block.hex(' ')}")
            print(f"Shift Register (SR): {sr.hex(' ')}")
            
            print(f"\n1. Criptografando SR com Vigenère:")
            encrypted_sr = passo_a_passo_vigenere(sr, True)
            
            print(f"\n2. Operação XOR:")
            processed = []
            for j in range(len(block)):
                b = block[j]
                e = encrypted_sr[j]
                xor_result = b ^ e
                print(f"   Byte {j}: {b:3d} ^ {e:3d} = {xor_result:3d}")
                processed.append(xor_result)
            processed = bytes(processed)
            print(f"   Resultado XOR: {processed.hex(' ')}")
            
            result += processed
            sr = block
            print(f"3. Novo SR (bloco ciphertext): {sr.hex(' ')}")
    
    if encrypt:
        print(f"\n=== RESULTADO FINAL CFB ===")
        print(f"Ciphertext completo: {result.hex(' ')}")
        return result
    else:

        print(f"\n=== RESULTADO FINAL CFB ===")
        print(f"Texto descriptografado: {result.decode()}")
        return result

if __name__ == "__main__":
    plaintext = b"CRIPTOGRAFIA"
    iv = b"INIT!"

    print(f"Chave: {key_string} (bytes: {KEY_BYTES})")
    print(f"Texto original: {plaintext.decode()}")

    # Modo ECB
    c_ecb = ecb(plaintext, True)
    p_ecb = ecb(c_ecb, False)
    print(f"\n[ECB] Ciphertext: {c_ecb.hex(' ')}")
    print(f"[ECB] Decrypted: {p_ecb.decode()}")
    print(f"[ECB] Header: {header('ECB', plaintext).hex(' ')}")

    # Modo CFB
    c_cfb = cfb(plaintext, iv, True)
    p_cfb = cfb(c_cfb, iv, False)
    print(f"\n[CFB] IV: {iv.decode()}")
    print(f"[CFB] Ciphertext: {c_cfb.hex(' ')}")
    print(f"[CFB] Decrypted: {p_cfb.decode()}")
    print(f"[CFB] Header: {header('CFB', plaintext, iv).hex(' ')}")
    
    print(f"\n{'='*80}")
    print("EXECUTANDO PASSO A PASSO DETALHADO")
    print(f"{'='*80}")
    
    # Passo a passo ECB
    print(f"\n{'='*20} ECB CRIPTOGRAFIA {'='*20}")
    passo_a_passo_ecb(plaintext, True)
    
    print(f"\n{'='*20} ECB DESCRIPTOGRAFIA {'='*20}")
    passo_a_passo_ecb(c_ecb, False)
    
    # Passo a passo CFB
    print(f"\n{'='*20} CFB CRIPTOGRAFIA {'='*20}")
    passo_a_passo_cfb(plaintext, iv, True)
    
    print(f"\n{'='*20} CFB DESCRIPTOGRAFIA {'='*20}")
    passo_a_passo_cfb(c_cfb, iv, False)