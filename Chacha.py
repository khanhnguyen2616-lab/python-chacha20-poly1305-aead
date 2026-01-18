import struct

def rotl(a, b):
    return ((a << b) & 0xFFFFFFFF) | (a >> (32 - b))

def quarter_round(a, b, c, d, state):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF; state[d] ^= state[a]; state[d] = rotl(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF; state[b] ^= state[c]; state[b] = rotl(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF; state[d] ^= state[a]; state[d] = rotl(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF; state[b] ^= state[c]; state[b] = rotl(state[b], 7)

def chacha20_block(key, counter, nonce):
    ctx = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    ctx += list(struct.unpack("<8I", key))
    ctx += [counter]
    ctx += list(struct.unpack("<3I", nonce))

    working = ctx[:]
    for _ in range(10):
        # Column rounds
        quarter_round(0, 4, 8, 12, working)
        quarter_round(1, 5, 9, 13, working)
        quarter_round(2, 6, 10, 14, working)
        quarter_round(3, 7, 11, 15, working)
        # Diagonal rounds
        quarter_round(0, 5, 10, 15, working)
        quarter_round(1, 6, 11, 12, working)
        quarter_round(2, 7, 8, 13, working)
        quarter_round(3, 4, 9, 14, working)

    return b"".join(struct.pack("<I", (working[i] + ctx[i]) & 0xFFFFFFFF) for i in range(16))

def chacha20_encrypt(key, counter, nonce, data):
    res = bytearray()
    for i in range(0, len(data), 64):
        keystream = chacha20_block(key, counter, nonce)
        chunk = data[i:i+64]
        for j in range(len(chunk)):
            res.append(chunk[j] ^ keystream[j])
        counter += 1
    return bytes(res)

def poly1305_mac(msg, key):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i+16]
        # Thêm bit thứ 129 (hoặc byte 0x01 vào cuối block)
        n = int.from_bytes(chunk, "little") + (1 << (8 * len(chunk)))
        acc = ((acc + n) * r) % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")

def pad16(data):
    return b"\x00" * ((16 - len(data) % 16) % 16)

def chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
    nonce = constant + iv
    # Sinh Poly1305 key (block 0)
    otk = chacha20_block(key, 0, nonce)[:32]
    # Mã hóa (bắt đầu từ block 1)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
    # Tạo dữ liệu xác thực
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += struct.pack("<QQ", len(aad), len(ciphertext))
    # Tính Tag
    tag = poly1305_mac(mac_data, otk)
    return ciphertext, tag

# Bổ sung hàm giải mã để kiểm tra tính toàn vẹn
def chacha20_aead_decrypt(aad, key, iv, constant, ciphertext, tag):
    nonce = constant + iv
    otk = chacha20_block(key, 0, nonce)[:32]
    
    mac_data = aad + pad16(aad)
    mac_data += ciphertext + pad16(ciphertext)
    mac_data += struct.pack("<QQ", len(aad), len(ciphertext))
    
    calc_tag = poly1305_mac(mac_data, otk)
    if calc_tag != tag:
        raise ValueError("Tag không khớp! Dữ liệu đã bị chỉnh sửa.")
        
    return chacha20_encrypt(key, 1, nonce, ciphertext)
# ======================== TEST VECTOR RFC 8439 ========================
if __name__ == "__main__":
    key = bytes.fromhex(
        "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f "
        "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"
    )

    constant = bytes.fromhex("07 00 00 00")
    iv = bytes.fromhex("40 41 42 43 44 45 46 47")  # 8 bytes

    aad = bytes.fromhex("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7")

    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    )

    print(f"Plaintext length: {len(plaintext)} bytes\n")

    ciphertext, tag = chacha20_aead_encrypt(aad, key, iv, constant, plaintext)

    print("Ciphertext (hex):")
    print(' '.join(f'{b:02x}' for b in ciphertext))

    print("\nTag (hex):")
    print(' '.join(f'{b:02x}' for b in tag))

