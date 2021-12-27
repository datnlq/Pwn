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