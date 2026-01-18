def simulate_poly1305_vector_8():
    # 1. Khởi tạo các giá trị theo Vector #8
    # r = 1 (sau khi đã clamp)
    r = int.from_bytes(bytes.fromhex("01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"), "little")
    # s = 0
    s = int.from_bytes(bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"), "little")
    
    # Dữ liệu đầu vào gồm 3 block (M1, M2, M3) mỗi block dài 16 byte
    m1_hex = "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
    m2_hex = "FB FE FE FE FE FE FE FE FE FE FE FE FE FE FE FE"
    m3_hex = "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01"
    
    data_blocks = [
        bytes.fromhex(m1_hex),
        bytes.fromhex(m2_hex),
        bytes.fromhex(m3_hex)
    ]

    p = (1 << 130) - 5
    acc = 0

    print(f"--- Bắt đầu mô phỏng Poly1305 (Vector #8) ---")
    print(f"Số nguyên tố p = 2^130 - 5")
    
    # 2. Quá trình tính toán đa thức
    for i, chunk in enumerate(data_blocks):
        # Mỗi block cộng thêm 2^128 (đánh dấu block đầy đủ)
        n = int.from_bytes(chunk, "little") + (1 << 128)
        
        # Công thức: Acc = ((Acc + n) * r) % p
        acc = ((acc + n) * r) % p
        
        print(f"Sau Block M{i+1}: Acc = {hex(acc)}")

    # 3. Kết quả cuối cùng
    # tag = (acc + s) mod 2^128
    final_tag_int = (acc + s) % (1 << 128)
    final_tag_bytes = final_tag_int.to_bytes(16, "little")

    print(f"--- Kết quả ---")
    print(f"Acc cuối cùng (trước khi cộng s): {acc} (Hex: {hex(acc)})")
    print(f"Tag (sau khi mod 2^128): {final_tag_bytes.hex(' ')}")
    
    if acc == 0:
        print("\n=> Giải thích: Kết quả trung gian đạt đúng giá trị 2^130 - 5 nên bị reset về 0 bởi phép mod p.")

if __name__ == "__main__":
    simulate_poly1305_vector_8()