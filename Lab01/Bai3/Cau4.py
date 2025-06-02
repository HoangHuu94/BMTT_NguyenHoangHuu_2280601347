#Chương trình để truy cập vào các phần từ đầu tiền và cuối cùng trong một Tuple
def access_tuple_elements(tup):
    first_element = tup[0]
    last_element = tup[-1]
    return first_element, last_element
#Nhập tuple từ người dùng và xử lý chuỗi
input_tuple = eval(input("Nhập tuple, ví dụ (1,2,3,4): "))
#Sử dụng hàm và in kết quả
first, last = access_tuple_elements(input_tuple)
print("Phần tử đầu tiên trong tuple là:", first)
print("Phần tử cuối cùng trong tuple là:", last)