#Hàm kiểm tra số nhị phân
def chiahetcho5(sonhiphan):
    # Chuyển đổi số nhị phân thành số thập phân
    sothapphan = int(sonhiphan, 2) % 5
    if sothapphan %5 == 0:
        return True
    else:
        return False
# Nhập số nhị phân từ người dùng
chuoinhihphan = input("Nhập số nhị phân (phân tách bởi dấu phẩy): ")
# Tách chuỗi nhị phân thành danh sách các số nhị phân và kiểm tra số chia hết cho 5
danh_sach_so = chuoinhihphan.split(',')
sochiahetcho5 = [so for so in danh_sach_so if chiahetcho5(so)]
# In danh sách các số chia hết cho 5
if len(sochiahetcho5) > 0:
    ketqua = ', '.join(sochiahetcho5)
    print("Các số nhị phân chia hết cho 5 là:", ketqua)
else:
    print("Không có số nhị phân nào chia hết cho 5.")