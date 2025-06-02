import ecdsa
import os

# Tạo thư mục chứa khóa nếu chưa tồn tại
if not os.path.exists('cipher/ecc/keys'):
    os.makedirs('cipher/ecc/keys')

class ECCCipher:
    def __init__(self):
        pass

    def generate_keys(self):
        # Tạo khóa riêng tư (Signing Key)
        sk = ecdsa.SigningKey.generate()
        # Lấy khóa công khai từ khóa riêng tư
        vk = sk.get_verifying_key()

        # Lưu khóa riêng tư vào file
        with open('cipher/ecc/keys/privateKey.pem', 'wb') as p:
            p.write(sk.to_pem())

        # Lưu khóa công khai vào file
        with open('cipher/ecc/keys/publicKey.pem', 'wb') as p:
            p.write(vk.to_pem())

    def load_keys(self):
        # Đọc khóa riêng tư từ file
        with open('cipher/ecc/keys/privateKey.pem', 'rb') as p:
            sk = ecdsa.SigningKey.from_pem(p.read())

        # Đọc khóa công khai từ file
        with open('cipher/ecc/keys/publicKey.pem', 'rb') as p:
            vk = ecdsa.VerifyingKey.from_pem(p.read())

        return sk, vk

    def sign(self, message, private_key):
        # Ký dữ liệu với khóa riêng tư
        return private_key.sign(message.encode('ascii'))

    def verify(self, message, signature, public_key):
        try:
            # Xác minh chữ ký với khóa công khai
            return public_key.verify(signature, message.encode('ascii'))
        except ecdsa.BadSignatureError:
            return False
