import os

cmd ='curl "https://www.wireshark.org/download/automated/data/manuf" > /home/kali/Detection_Testing/wireshark-oui-list.txt'
print(cmd)
os.system(cmd)

f = open(r'/home/kali/Detection_Testing/wireshark-oui-list.txt', "r+", encoding='utf-8')

new_file = []

for i in range(10):
  next(f)

for line in f:
  splits = line.split('\t')

  splits_twodots = splits[0].split(':')

  if( len(splits_twodots) < 4 ):  # 24 bits

    new_file.append(splits[0].strip() + '\t' + splits[2].strip() + '\n')

with open(r"/home/kali/Detection_Testing/wireshark-oui-list.txt", "w+", encoding='utf-8') as f:
  for i in new_file:
    f.write(i)