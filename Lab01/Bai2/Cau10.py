#Hàm nhận vào 1 chuỗi và trả lại chuổi ngược của nó
def reverse_string(s):
    return s[::-1]
#Sử dụng hàm và in kết quả
input_string = input("Nhập vào một chuỗi: ")    
print("Chuỗi ngược lại là:", reverse_string(input_string))