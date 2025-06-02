#Chương trình để tính tổng các số chẵn trong 1 list
def tinhtongsochan(lst):
    tong = 0
    for so in lst:
        if so % 2 == 0:
            tong += so
    return tong
#Nhập danh sách số nguyên từ người dùng và xử lý chuỗi
input_list = input("Nhập danh sách số nguyên (cách nhau bởi dấu phẩy): ")
number = list(map(int, input_list.split(',')))
#Sử dụng hàm và in kết quả
tong_so_chan = tinhtongsochan(number)
print("Tổng các số chẵn trong danh sách là:", tong_so_chan)



