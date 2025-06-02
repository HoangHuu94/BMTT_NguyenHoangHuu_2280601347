#Tạo 1 danh sách rỗng để lưu kết quả
j=[]
#duyệt qua tất cả các số
for i in range(2000, 3201):
    if (i %7 ==0) and (i %5 !=0):
        j.append(str(i))
print(",".join(j))