import hashlib

def calculate_sha256_hash(data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data.encode('utf-8'))  # Chuyển đổi dữ liệu thành bytes và băm
    return sha256_hash.hexdigest()            # Trả về chuỗi hash ở dạng hex

data_to_hash = input("Nhập dữ liệu cần băm: ")
hash_value = calculate_sha256_hash(data_to_hash)
print("Giá trị băm SHA-256: ", hash_value)