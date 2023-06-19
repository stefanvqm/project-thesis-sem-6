x = [66, 44, 142, 122, 98, 39, 215, 188, 161, 53, 11, 62, 43, 183, 39, 159, 120, 151, 184, 123, 182, 133, 75, 120, 60, 96, 232, 3, 17, 174, 48, 121]
length = 8

res = ""

for i in x:
    zeros = length - len(str(bin(i)[2:]))
    res += str((zeros * "0") + bin(i)[2:])


print(res)
print(len(res))
