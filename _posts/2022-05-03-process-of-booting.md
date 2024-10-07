---
layout: post
title: Linux Kernel - PC 부팅 과정
date: 2022-05-03 18:01:00 +0900
categories: [Security, Kernel]
tags: [kernel, bios, booting]
media_subpath: /assets/img/
---

![booting](0503-process-of-booting/01-booting.jpg){: width="50%" height="50%"}

<center>컴퓨터의 부팅 과정에 대해 이해해 보자.</center>

---

부팅은 PC가 켜진 후에 OS가 실행되기 전까지 수행되는 일련의 작업 과정을 의미한다.

부팅 과정에 수행하는 작업에는 프로세서 초기화(멀티코어 관련 처리 포함), 메모리와 외부 디바이스 검사 및 초기화, 부트 로더를 메모리에 복사하고 OS를 시작하는 과정 등이 포함된다.

### **1. Power 누르기**

![button](0503-process-of-booting/02-button.png){: width="200" height="200"}
*Created by srip - Flaticon*

컴퓨터의 전원을 누르면, 메인보드에 전력이 들어온다.

뒤이어 메인보드에 연결된 장치(CPU, Memory, Disk, etc.)에도 전력이 들어온다.

### **2\. BIOS 동작**

![bios](0503-process-of-booting/03-bios.jpg)
*BusinessLine, "BIOS is history. Long live BIOS!"*

CPU가 ROM(Read-Only Memory)에 저장된 BIOS(Basic Input/Output System)을 실행한다. BIOS는 메인보드에 포함된 펌웨어(Firmware)의 일종으로, 이름 그대로 입출력을 담당하는 작은 프로그램이다. 일반적으로 메인보드 상에 있는 ROM이나, 플래시 메모리에 존재하며, 전원이 켜짐과 동시에 프로세서가 가장 먼저 실행하는 코드이다. BIOS는 POST(Power On Self Test)라는 과정으로, CPU, Memory, CMOS RAM, 주변 장치 등을 테스트하고 초기화하는 작업을 진행한다.

이후에, BIOS는 CMOS(Complementary Metal–Oxide–Semiconductor) chip에 접근하여, CMOS에 저장된 BIOS 설정 값을 불러들이고 동작한다. 이 설정 값에서 RTC(Real-Time Clock) chip은 시스템의 날짜와 시간을, NVRAM(Non-Volatile RAM) chip은 메모리 크기, 드라이브(플로피 및 하드디스크 등) 타입, 부팅 순서 및 구성 정보를 저장한다. 이 두 개의 저장소가 CMOS 방식으로 만들어졌기 때문에, CMOS chip이라고 부르기도 한다. 메인보드에 CR2032 배터리가 존재하는 이유가 RTC chip 때문이다.

![bios](0503-process-of-booting/04-bios.jpg)
*BIOS 화면*


즉, 컴퓨터를 부팅할 때, F2를 눌러서 BIOS 화면에 진입하면, 위 창을 띄우고 사용자가 임의로 설정할 수 있게 하는 인터페이스는 BIOS에, System Time과 같은 데이터는 CMOS에 존재하는 것으로 정리할 수 있겠다.

또한, 다음과 같은 의문이 남는다. BIOS는 Read-Only Memory에 존재하는데, 어떻게 펌웨어 업데이트를 진행할 수 있는 걸까? 내가 조사한 바로는, 요즘 ROM은 다 분류상으로 Electrically Erasable Programmable ROM(EEPROM)이라서, 전기적으로 내용 수정이 가능하다. 그렇기 때문에, BIOS 업데이트가 가능한 것이지 싶다.

### **3\. 부트 로더 이미지를 메모리로 복사**

마지막으로, BIOS는 Master Boot Record(MBR)을 읽어서 부트 로더, 혹은 부트스트랩(Bootstrap) 코드를 0x7C00 메모리 주소에 올린다. 부트 로더는 플로피 디스크나 하드 디스크와 같은 외부 저장 매체에 있으며, 저장 매체의 가장 첫 번째 섹터를 MBR이라고 한다. 섹터(Sector)는 디스크를 구성하는 단위(512 Bytes)이다. 즉, 부트 로더는 512 Byte의 제한된 공간에 존재하는 프로그램이기에, 대부분의 부트 로더는 OS 이미지를 메모리로 복사하고 제어를 넘겨주는 정형화된 작업을 수행한다.

![mbr](0503-process-of-booting/05-mbr.png)
*임베디드 시스템 엔지니어를 위한 리눅스 커널 분석*

MBR에는 부트 로더(0~445 Bytes) + 파티션 테이블(446~510 Bytes) + 시그니처(511~512 Bytes)로 이루어져 있는 것이 일반적이다. 파티션은 디스크 영역을 논리적으로 구분하는 단위로, MBR 영역에는 4개의 파티션 엔트리가 있으며, 파티션 엔트리에서 정의된 영역은 독립된 공간을 보장받는다. 또한, 시그니처는 첫 번째 섹터에 위치한 512바이트가 MBR인지 확인하기 위한 매직 넘버(0x55, 0xAA)이다.

부트 로더의 예시로는 다음 두 가지를 소개하고 싶다.

\- LILO(Linux Loader, 예전 리눅스 로더)

\- GRUB(GRand Unified Bootloader, GNU에서 개발한 멀티 부트 로더)가 있다.

이 상태에서, 이전에 설명하였던 bzImage에 실행 흐름만 넘겨주면, 자동으로 커널 이미지를 메모리에 로드하고, 압축도 해제하며, 마침내 리눅스 커널이 실행될 것이다.

---

### **References**

\[1\] 정보문화사, "롬 바이오스 알아보기", [https://m.post.naver.com/viewer/postView.naver?volumeNo=14746758&memberNo=15488377](https://m.post.naver.com/viewer/postView.naver?volumeNo=14746758&memberNo=15488377)

\[2\] 남상규, "임베디드 시스템 엔지니어를 위한 리눅스 커널 분석 - 2장. Makefile 분석", [http://wiki.kldp.org/KoreanDoc/html/EmbeddedKernel-KLDP/understanding-booting-process.html](http://wiki.kldp.org/KoreanDoc/html/EmbeddedKernel-KLDP/understanding-booting-process.html)

\[3\] dustjs159, "컴퓨터 부팅 과정", [https://velog.io/@dustjs159/%EC%BB%B4%ED%93%A8%ED%84%B0-%EB%B6%80%ED%8C%85-%EA%B3%BC%EC%A0%95](https://velog.io/@dustjs159/%EC%BB%B4%ED%93%A8%ED%84%B0-%EB%B6%80%ED%8C%85-%EA%B3%BC%EC%A0%95)

\[4\] melonicedlatte, "MBR과 부트로더의 개념 정리", [http://melonicedlatte.com/computerarchitecture/2019/09/11/171200.html](http://melonicedlatte.com/computerarchitecture/2019/09/11/171200.html)

\[5\] HYUN, "#13 운영체제 \| 간단한 부팅 과정", [https://velog.io/@hyun0310woo/13-%EC%9A%B4%EC%98%81%EC%B2%B4%EC%A0%9C-%EB%B6%80%ED%8C%85](https://velog.io/@hyun0310woo/13-%EC%9A%B4%EC%98%81%EC%B2%B4%EC%A0%9C-%EB%B6%80%ED%8C%85)

\[6\] PRONEER, "CMOS와 BIOS의 차이를 아는가?" [http://forensic-proof.com/archives/181](http://forensic-proof.com/archives/181)

\[7\] Sandip Roy, "BIOS vs. CMOS vs. UEFI", [https://www.baeldung.com/cs/bios-vs-cmos-vs-uefi](https://www.baeldung.com/cs/bios-vs-cmos-vs-uefi)

\[8\] DELL Technologies, "POST 및 부팅 프로세스", [https://www.dell.com/support/kbdoc/ko-kr/000128270/post-%EB%B0%8F-%EB%B6%80%ED%8C%85-%ED%94%84%EB%A1%9C%EC%84%B8%EC%8A%A4](https://www.dell.com/support/kbdoc/ko-kr/000128270/post-%EB%B0%8F-%EB%B6%80%ED%8C%85-%ED%94%84%EB%A1%9C%EC%84%B8%EC%8A%A4)

\[9\] QUASAR ZONE, "BIOS와 운영체제의 관계", [https://quasarzone.com/bbs/qf\_cmr/views/85439](https://quasarzone.com/bbs/qf_cmr/views/85439)

\[10\] COOLN, "잡담 \| 메인보드 방전시켜도 살아있는 오버값 ㄷㄷ;", [https://coolenjoy.net/bbs/overclock/808280](https://coolenjoy.net/bbs/overclock/808280)