#CHương trình đảo ngược các phần tử trong một danh sách
def reverse_list(lst):
    return lst[::-1]
#Nhập danh sách từ người dùng va xử lý chuỗi
input_list = input("Nhập danh sách số nguyên (cách nhau bởi dấu phẩy): ")
number = list(map(int, input_list.split(',')))
#Sử dụng hàm và in kết quả  
list_reversed = reverse_list(number)
print("Danh sách sau khi đảo ngược là:", list_reversed)