#chương trình để xóa một phần từ Dictionary theo key đã cho
def delete_element_from_dict(d, key):
    if key in d:
        del d[key]
        return True
    else:
        return False
#Sử dụng hàm và in kết quả
my_dict = {'a': 1, 'b': 2, 'c': 3, 'd': 4}
key_to_delete = 'b'
result = delete_element_from_dict(my_dict, key_to_delete)
if result:
    print(f"Phần tử đã được xóa khỏi Dictionary.", my_dict)
else:
    print(f"Phần tử không tồn tại trong Dictionary.",my_dict)
    