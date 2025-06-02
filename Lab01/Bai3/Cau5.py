#chương trình đếm số lần xuất hiện của các phần tử trong một list và lưu kết quả vào một Dictionary
def count_elements(lst):
    element_count = {}
    for element in lst:
        if element in element_count:
            element_count[element] += 1
        else:
            element_count[element] = 1
    return element_count
#Nhập danh sách số nguyên từ người dùng và xử lý chuỗi
input_string = input("Nhập danh sách số nguyên (cách nhau bởi dấu phẩy): ")
word_list = input_string.split(',')
#Sử dụng hàm và in kết quả
element_count = count_elements(word_list)   
print("Số lần xuất hiên của các phần tử trong danh sách là:", element_count)