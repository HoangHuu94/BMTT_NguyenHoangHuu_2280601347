#Hàm kiểm tra số nguyên tố
def kiemtrasonguyento(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
#Kiểm tra số nguyên tố và in kết quả
number = int(input("Nhập số nguyên dương: "))
if kiemtrasonguyento(number):
    print(f"{number} là số nguyên tố.")
else:
    print(f"{number} không phải là số nguyên tố.")