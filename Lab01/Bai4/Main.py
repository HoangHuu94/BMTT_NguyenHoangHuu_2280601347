from QuanLySinhVien import QuanLySinhVien

qlsv = QuanLySinhVien()

while True:
    print("\nCHƯƠNG TRÌNH QUẢN LÝ SINH VIÊN")
    print("***********************************")
    print("**          MENU                 **")
    print("**  1. Thêm sinh viên            **")
    print("**  2. Cập nhật thông tin sinh viên **")
    print("**  3. Xóa sinh viên bởi ID      **")
    print("**  4. Tìm kiếm sinh viên theo tên **")
    print("**  5. Sắp xếp sinh viên theo điểm trung bình **")
    print("**  6. Sắp xếp sinh viên theo tên **")
    print("**  7. Hiển thị danh sách sinh viên **")
    print("**  0. Thoát                     **")
    print("***********************************")
    key = int(input("Nhập tùy chọn: "))
    if key == 1:
        qlsv.nhapSinhVien()
        print("\nThêm sinh viên thành công!")
    elif key == 2:
        if qlsv.soLuongSinhVien() > 0:
            id = int(input("\nNhập ID: "))
            qlsv.updateSinhVien(id)
        else:
            print("\nDanh sách sinh viên trống!")
    elif key == 3:
        if qlsv.soLuongSinhVien() > 0:
            id = int(input("\nNhập ID: "))
            if qlsv.deleteById(id):
                print("\nXóa thành công!")
            else:
                print(f"\nSinh viên có ID = {id} không tồn tại.")
        else:
            print("\nDanh sách sinh viên trống!")
    elif key == 4:
        if qlsv.soLuongSinhVien() > 0:
            name = input("\nNhập tên để tìm kiếm: ")
            searchResult = qlsv.findByName(name)
            qlsv.showSinhVien(searchResult)
        else:
            print("\nDanh sách sinh viên trống!")
    elif key == 5:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.sortByDiemTB()
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sách sinh viên trống!")
    elif key == 6:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.sortByName()
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sách sinh viên trống!")
    elif key == 7:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("\nDanh sách sinh viên trống!")
    elif key == 0:
        print("\nBạn đã chọn thoát chương trình!")
        break
    else:
        print("\nHãy chọn chức năng trong menu!")