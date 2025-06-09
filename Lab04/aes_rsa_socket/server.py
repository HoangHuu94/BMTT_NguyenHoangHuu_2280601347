from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# 1. Khởi tạo socket máy chủ (TCP/IP)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))  # Gắn địa chỉ IP và cổng
server_socket.listen(5)  # Lắng nghe tối đa 5 kết nối

# 2. Sinh cặp khóa RSA (2048-bit) cho máy chủ
server_key = RSA.generate(2048)

# 3. Danh sách lưu các client đã kết nối cùng khóa AES tương ứng
clients = []

# -------------------- HÀM TIỆN ÍCH --------------------

# Hàm mã hóa tin nhắn bằng AES (CBC Mode)
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext  # Ghép IV + ciphertext

# Hàm giải mã tin nhắn AES
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

# -------------------- XỬ LÝ CLIENT --------------------

def handle_client(client_socket, client_address):
    print(f"[+] Client connected: {client_address}")

    # B1: Gửi khóa công khai RSA của máy chủ đến client
    client_socket.send(server_key.publickey().export_key(format='PEM'))

    # B2: Nhận khóa công khai RSA của client
    client_received_key = RSA.import_key(client_socket.recv(2048))

    # B3: Tạo khóa AES ngẫu nhiên và mã hóa bằng khóa RSA của client
    aes_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(client_received_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # B4: Gửi khóa AES đã mã hóa đến client
    client_socket.send(encrypted_aes_key)

    # B5: Lưu client và khóa AES vào danh sách
    clients.append((client_socket, aes_key))

    # B6: Nhận và phát tán tin nhắn giữa các client
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break

            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print(f"[{client_address}] {decrypted_message}")

            # Nếu nhận 'exit' thì thoát
            if decrypted_message.lower() == "exit":
                break

            # Gửi lại tin nhắn cho các client khác
            for client, key in clients:
                if client != client_socket:
                    encrypted = encrypt_message(key, decrypted_message)
                    client.send(encrypted)

        except Exception as e:
            print(f"[!] Error with {client_address}: {e}")
            break

    # B7: Xóa client và đóng kết nối
    clients.remove((client_socket, aes_key))
    client_socket.close()
    print(f"[-] Connection closed: {client_address}")

# -------------------- VÒNG LẶP CHÍNH --------------------

print("[*] Server is running and waiting for connections...")

while True:
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address)
    )
    client_thread.start()
