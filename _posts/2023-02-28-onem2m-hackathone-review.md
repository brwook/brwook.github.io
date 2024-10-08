---
layout: post
title: "제6회 KETI 모비우스 국제 개발자 대회 후기"
date: 2023-02-28 19:00:00 +0900
categories: [Review]
tags: [oneM2M, hackathon, review]
media_subpath: /assets/img/2023-02-28-onem2m
---

![onem2m2](onem2m8.jpg)

## 개요

---

모비우스 국제 개발자 대회라고 쓰고, oneM2M Hackathon이라고 부른다. 한국의 KETI(한국전자기술연구원)와 TTA(한국정보통신기술협회)에서, 그리고 유럽의 ETSI(유럽전기통신표준협회)에서 공동으로 주최하는 행사이고, 이 세 조직과 그 외 여러 조직이 공동으로 개발한 것이 oneM2M 프로토콜 및 플랫폼이다.

- oneM2M (one Machine-To-Machine)
  - 에너지, 교통, 국방, 공공서비스 등 산업별로 종속적이고 폐쇄적으로 운영되는, 파편화된 서비스 플랫폼 개발 구조를 벗어나 **응용서비스 인프라(플랫폼) 환경을 통합하고 공유하기 위한 사물인터넷 공동서비스 플랫폼 개발**을 위해 발족된 사실상 표준화 단체
  - 전세계 지역별 표준 개발기구인 TTA(한국), ETSI(유럽), ATIS/TIA(북미),CCSA(중국), ARIB/TTC(일본)등 7개의 SDO(Standard Development Organization)가 공동으로 설립

![onem2m6](onem2m6.png)

- Mobius
  - oneM2M 국제 표준을 기반으로 IoT(Internet of Things) 서비스 제공을 위해 다양한 IoT Device 정보를 관리하고, 이들 **IoT Device의 접근 제어, 인증, 사용자 관리, 복수의 IoT 서비스 조합을 제공**하여 어플리케이션을 통해 서비스하기 위한 플랫폼

![onem2m7](onem2m7.png)

내가 참여한 대회는 2022 International oneM2M Hackathon이며, 22년 10월 4일에 시작해 11월 21일까지 oneM2M 플랫폼을 활용하여 주요 환경/사회 문제를 해결하는 IoT 솔루션을 만들어서 제출하면 되었다.

해당 대회를 알게 된 경위는.. 정보보호학과 전공 수업 중에 "오픈소스SW설계"라는 강의가 있는데, 해당 강의 교수님께서 참여를 독려해주셨다. 그래서, 우리 팀은 부랴부랴 주제를 정하고 국제 개발자 대회에 개발 아이디어를 신청하였던 것 같고, 신청 마지막 날에 신청서도 어찌저찌 작성해서 제출을 마쳤던 것 같다. 모든 팀원이 밤을 새면서 주제를 정하고, 개발 아이디어에 대해 설명을 구체화하느라 또 다 같이 노력했던 게 아직도 기억에 남는다.

대회를 진행할 때는 KETI 측에서 IoT 개발에 필요한 라즈베리파이 장비와 센서를 제공해준다. 또한, 대회에 참여하는 팀은 17개 팀 정도 되었고, 그 중에서 절반 정도의 팀(총 8팀)이 상을 받을 수 있던 상황이라 아주 햅삐했다. 대학생뿐만 아니라, 현직 직장인도 참여를 권장하고 있으니 관심 있는 사람은 올해 대회에 팀을 꾸려 참가하면 좋을 것 같다.

## 프로젝트 주제

---

우리 팀의 주제는 '스마트 스쿨버스'로, 어린이 통학차량에 설치할 수 있는 스마트 안심통학 솔루션이라고 볼 수 있다. 당시 생각해 본 주제로는 비콘을 활용한 지하철 지하철 현재위치 확인, 소화기 압력계 관리, 하수구 막힘 관리 등이 있었는데, 교수님과의 상담 이후 다른 주제가 더 좋을 것 같다는 생각이 들어서 바꿨다.

그러다가, 아래 기사들을 보게 됐다.

![onem2m1](onem2m1.png)
_[https://news.kbs.co.kr/news/view.do?ncd=5383007](https://news.kbs.co.kr/news/view.do?ncd=5383007)_

2015년부터 시행된 어린이 통학차량 안전기준을 강화한 도로교통법 개정안(세림이법)에 따르면, 어린이 통학차량에는 아이들의 승·하차를 돕는 보호자, 즉 동승자가 반드시 탑승해야 하지만 이를 지키지 않는 경우가 있다는 것을 알게 되었다.

![onem2m3](onem2m3.jpg)
_[http://www.sisajournal-e.com/news/articleView.html?idxno=260788](http://www.sisajournal-e.com/news/articleView.html?idxno=260788)_

그리고 경찰청이 제출한 '어린이 통학버스 통계자료'에 따르면, 교통 순찰 인원 1명당 관리해야 하는 어린이 통학버스 대수가 최소 18대부터 194대에 이르기 때문에 교통 순찰 인원이 턱없이 모자라다는 것을 알게 되었다.

그래서 처음에는 얼굴인식을 통한 동승자 확인만 수행하려다가, 이것저것 '스마트'한 걸(버스 도착 알림, 슬리핑차일드 체크) 붙이다보니까 스마트 스쿨버스가 되었다. 더 자세한 설명과 깃허브 링크는 아래 hackster 링크에서 확인할 수 있으며, oneM2M이라 검색하면 다른 대회 수상작도 볼 수 있을 것이다. 데모 영상도 아래 첨부하였다!

{% include youtubeplayer.html id='5RGtvrRLieo' %}

- Hackster 링크 : [https://www.hackster.io/spectacle/smart-school-bus-f4bae0](https://www.hackster.io/spectacle/smart-school-bus-f4bae0)


## 개발 과정

---

![onem2m4](onem2m4.png)

우리 프로젝트의 전체 구조도이다. 일단 라즈베리파이와 연동된 센서에서 데이터를 측정하고, 그 데이터를 클라우드에 있는 모비우스 서버로 보낸다. 모비우스 서버가 데이터를 받으면, oneM2M 플랫폼의 기능 중 하나인 `subscription/notification`을 통해 파이썬 어플리케이션으로 데이터가 전송된다. 파이썬 어플리케이션은 데이터를 계속 모니터링하고 있다가, 특정 조건을 만족시키면, 스마트폰에 푸시 알람을 보내거나 액츄에이터를 실행하는 명령어를 모비우스 서버에 보낸다.

이 서비스에서 내가 맡은 부분은 아래와 같다.

![onem2m5](onem2m5.png)

oneM2M 플랫폼(Mobius, &Cube Thyme, TAS)을 직접 구축하고, 데이터를 연동할 수 있도록 하였다. 또한, 모니터링 엔티티를 파이썬 코드로 구현하였고, 파이썬 기본 모듈인 `HTTPServer`로 구현하였다. 맨 처음에는 Flask를 활용하여 간단하게 구현하고 있었으나, Mobius 플랫폼에 `Subscription`을 등록하고, 지속적으로 `Notification`을 받으려면 HTTP 연결이 계속 살아 있어야 했는데(keep-alive), 여기서 Flask로 구현하는데 애를 먹었다. 그러다가, 기존에 다른 프로젝트에서는 어떻게 구현했는지 찾다가, `HTTPServer` 모듈로 구현한 것이 `Notification`을 상대적으로 잘 받길래, 해당 모듈로 코드를 재수정했다. 

Mobius 플랫폼은 대회 참여의 기본 전제 조건이었고, IoT 센서 및 액츄에이터에서 데이터를 주고 받기 위해서는 별도의 장치가 필요했는데 여기서 사용된 것이 &Cube Thyme과 TAS(Thing Adaptation Software)이다. &Cube에도 lavender, rosemary 등 여러 종류가 있는 것으로 아는데, 단말 디바이스와 통신하기 위한 IoT 플랫폼이면서 기존에 자료를 찾아볼 수 있었던 Thyme을 선택하여 개발하였다.

가장 기억에 남는 것은 밤새서 GPS 센서 연동을 수행할 때이다. 분명 GPS 센서를 제대로 설치했는데, 라즈베리파이에서는 센서 데이터를 전혀 잡을 수 없었다. 알고 보니, GPS 센서는 건물 내부가 아니라 천장이 뚫린 외부에서 수행해야 작동함을 알게 되었고, 새벽에 노트북, 라즈베리파이와 센서, 핫스팟을 튼 휴대폰을 들고 오들오들 떨면서 코딩을 했던 것이 가장 기억에 남는다.

&Cube Thyme과 TAS를 구축할 때엔 구글에 떠돌아다니는 공식 Docs도 많이 도움되었으나, [seunghwanly님의 블로그](https://velog.io/@seunghwanly/RADAR-%EC%84%A4%EC%A0%95%ED%95%98%EB%9F%AC-%EA%B0%80%EA%B8%B0)가 정말 큰 도움이 되었다. 👍

## 결과

---

![onem2m10](onem2m10.jpg)

2등상인 ETSI 원장상을 수상할 수 있었다. 프로젝트를 제출하고나서는 장난 삼아 2등상은 받아야지 하면서 농담을 주고받던 기억이 있는데, 정말 상을 받게 되어서 놀랐다.

![onem2m9](onem2m9.jpg)
_[https://www.facebook.com/sejongpr/photos/pcb.2084431508422873/2084431428422881](https://www.facebook.com/sejongpr/photos/pcb.2084431508422873/2084431428422881)_

또한, 세종대학교 '23년 2월 이달의 세종인' 포스트에 포함되었다. 평소 눈팅만 해오던 게시글인데 내가 올라가게 될 줄은 몰랐다 ㅎㅎ.. 기분이 아주 좋더라.

## 후기

---

### 요약

- 2022 International oneM2M Hackathon에 세종대학교 정보보호학과 팀원들과 함께 출전하였다.
- Mobius 플랫폼을 활용하여, '스마트 스쿨버스'라는 주제로 IoT 서비스를 개발하였다.
- 정말 감사하게도 2등상인 ETSI 원장상을 수상할 수 있었다. *(Shout out to 텍사스출신 팀원..)*

### 배운 점

- oneM2M hackathon에서 oneM2M 프로토콜 관련 백엔드를 모두 커버하다보니까, Mobius 플랫폼과 &Cube Thyme, 그리고 TAS의 역할에 대한 이해도를 높일 수 있었다.
- 해커톤을 진행할 때, 나와 팀원들의 서비스 구현 명세를 지속적으로 일치시키는 것이 중요함을 알게 되었다. 이 또한 팀원과의 소통의 일환으로써 수행되었어야 했다.
- 개발을 하려면 깃을 꼭 활용하여 버전 관리를 수행하자. 안 그러면 짬뽕 코드가 될 수 있다 ㅜㅜ.

