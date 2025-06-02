sogiolam = float(input("Nhập số giờ làm mỗi tuần:"))
luonggio = float(input("Nhập thù lao trên mỗi giờ làm tiêu chuẩn:"))
giotieuchuan = 44 #Số giờ làm chuẩn mỗi tuần
giovuotchuan = max (0, sogiolam-giotieuchuan) #so giờ làm vượt chuẩn mỗi tuần
thuclinh = giotieuchuan* luonggio + giovuotchuan*luonggio*1.5 #tính tôngt thu nhập
print (f"Số tiền thực lĩnh của nhân viên:{thuclinh}")