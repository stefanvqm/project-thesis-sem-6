

line = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
n = 2
x = [f"0x{line[i:i+n]}" for i in range(0, len(line), n)]

print(x)
