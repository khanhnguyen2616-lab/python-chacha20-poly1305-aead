# python-chacha20-poly1305-aead
Mô phỏng cách thức vận hành của thuật toán Chacha20-Poly1305 dựa trên RFC 8439 nhằm mục đích giáo dục, nghiên cứu

##  Mục tiêu dự án
- Học cách hoạt động của mã hóa dòng (Stream Cipher) ChaCha20.
- Tìm hiểu cách xác thực dữ liệu với Poly1305.
- Thực hành lập trình Python xử lý dữ liệu nhị phân (struct, bytes).

## Tính năng
- Mã hóa và giải mã chuẩn RFC 8439.
- Đã kiểm tra (verify) với các bộ Test Vectors tiêu chuẩn.
- Code đơn giản, có chú thích để dễ hiểu.

##  Cách chạy thử
Bạn chỉ cần tải file `chacha20_aead.py` về và chạy bằng lệnh:
```bash
python3 chacha20_aead.py
