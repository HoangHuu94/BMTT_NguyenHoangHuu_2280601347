#Chương trình để tạo 1 Tuple từ 1 list nhập vào từ bàn phím
def create_tuple_from_list(lst):
    return tuple(lst)
#Nhập danh sách số nguyên từ người dùng và xử lý chuỗi
input_list = input("Nhập danh sách số nguyên (cách nhau bởi dấu phẩy): ")
number = list(map(int, input_list.split(',')))
#Sử dụng hàm và in kết quả
my_tuple = create_tuple_from_list(number)
print("Danh sách số nguyên là:", number)
print("Tuple được tạo từ danh sách là:", my_tuple)