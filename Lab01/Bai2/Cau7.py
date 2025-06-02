print("Nhập văn bản:(Nhâp done để kết thúc):")
lines = []
while True:
    line = input()
    if line.lower() == 'done':
        break
    lines.append(line)  
print("Văn bản đã nhập được viết lại:")
for line in lines:
    print(line.upper())