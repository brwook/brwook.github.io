---
layout: post
title: "Incognito 2022 Hacking Conference 후기"
date: 2023-03-26 22:00:00 +0900
categories: [Review]
tags: [CTF, Conference, review]
media_subpath: /assets/img/2023-03-26-incognito
---

![poster](1.jpg)

제 생애 처음으로, Incognito 컨퍼런스 참여 및 발표를 하였습니다. 작년에 회장 일을 하면서, 최대한 바깥으로 활동 영역을 넓히자라는 생각으로 Incognito와 HSpace Partner를 신청하였는데, 오프라인으로 활동하는 것은 처음이어서 설레면서도 발표할 생각에 걱정도 되었습니다.

Incognito는 보안을 전공하는 대학생들의 전국 연합 컨퍼런스입니다. 전문가들의 지도 하에 연구 과제와 산출물을 선보이며 성취를 공유하는 장(場)으로, 제게는 지난 겨울 방학 동안 "Fuzzing 학습 및 상용 소프트웨어 취약점 분석"이라는 주제로 프로젝트를 진행했던 것을 발표하는 자리가 되었습니다. 25일에는 2023 HackTheon Sejong 대회가 있어서, 아쉽게도 첫 날에는 참여하지 못하였으나, 둘째 날에는 참여할 수 있었습니다.

이번 글에서는 컨퍼런스에 참여하여 들었던 내용에 대해 정리해 보고자 합니다.

### Xpdf 0-day Research + iOS SEPROM 분석 [충남대 ARGOS 진건승님]

---

Xpdf는 PDF viewer 및 여러 툴킷을 포함하는 오픈 소스 프로젝트입니다. Fuzzing101이라는 AFL++ 실습의 맨 처음 단계를 진행하고 Root Cause를 분석하면서 퍼징에 흥미가 생겼고, Xpdf 4.04 최신 버전에 대하여 퍼징을 수행하는 프로젝트를 떠올리셨다고 합니다. 퍼징 프로젝트가 처음인 팀원들이 있어서, 본인이 주도적으로 진행하였다고 이야기하셨고, 아무래도 조직의 장이라는 자리가 자신보다는 남을 이끌고 챙겨주고 하는 자리이기도 한 것 같습니다. 많이 공감되네요 ㅎㅎ..

AFL++을 통해서 퍼징을 진행하였는데 처음에는 코드 커버리지가 측정되지 않아(무슨 이유 때문이었는지는 까먹었네요.) 덤 퍼징 수준으로 AFL++ 퍼저를 돌리셨는데, 의외로 퍼징을 돌린지 1~2시간 만에 유효한 취약점이 발견되었고, 이를 바탕으로 Root Cause를 분석한 뒤 제보하셨다고 합니다. 그러나, Duplicate에 해당하는 취약점이어서 아쉽게도 CVE Number는 받을 수 없었다고 하셨습니다.

또한, Xpdf 5.0이 출시될 예정이라, 건승님께서 발견하신 취약점에 대해 패치하지 않고 있는 상황임을 설명해 주셨습니다. 이로 인해, 두 번째 주제인 iOS SEPROM 분석으로 프로젝트를 새롭게 시작하셨다고 하네요. 해당 프로젝트를 진행하다 보면, iOS 운영체제 상에서의 탈옥인 jail break를 수행할 수 있다고 합니다.

iOS SEPROM 분석이라는 주제가, 기존에 관심을 갖고 있지 않으면 흔하게 떠오르지는 않을 주제인 것 같은데, 어떤 계기로 해당 주제를 선택하셨는지 궁금해서 질문하려고 하였으나, 멈칫멈칫하다가 질문 시간을 놓쳐 아쉽게도 여쭤보질 못했네요 ㅜㅜ.

해당 주제에 대해서 구글링 해보면, 정보를 많이 찾을 수 없고 또 영어로 된 일종의 백서 같은 것이 있다고 하는데, 이를 바탕으로 한국어판 가이드 라인을 만드는 과정에 있다고 하셨습니다. 아직 제대로 된 내용은 들어볼 수 없었지만, 말로만 들어도 기대가 되는 작업이라 꼭 보고 싶었습니다.


### 패스워드 매니저 취약점 분석 [서울여대 SWLUG 윤희서님]

---

패스워드 매니저란 하나의 마스터 패스워드로 암호화된 데이터베이스에 접근하는 방식으로, 웹 서비스를 편리하게 이용할 수 있게 도와주는 서비스를 의미합니다. 패스워드 매니저가 브라우저 기반, 로컬 기반, 웹 기반으로 서비스가 존재하며, 평소에 저도 크롬 상에서 자주 사용하는, 편리한 기능이라 해당 서비스에서 취약점 분석을 수행한다기에 아주 흥미롭게 들었습니다.

여러 패스워드 매니저에서 로컬 사용자 권한을 얻을 경우, 쉽게 피해자(victim)의 PC에서 개인정보를 탈취할 수 있음을 선보이셨습니다. 로컬 경로에 저장된 암호화 파일과 키를 이용하여 AES256 복호화를 수행하거나, 브루트 포싱, 그리고 메모리 상에서 데이터를 탈취하는 등의 방법을 이용하셨는데, 이전에 알고 있던 정보도 있고 새롭게 알게 된 정보도 있어서 재밌었습니다. 그리고 이에 대한 대응책으로 TLS 사용, 메모리 삭제, 안전한 패스워드 삭제, 그리고 패스키(생체 정보를 활용한 보안)을 제시한 것도 재밌게 들었습니다. 다만 패스키가 새롭게 출시된 기술인 것 같은데, 정말 안전한가에 대해서는 물음표를 갖게 되었습니다. 다음에 해당 내용을 조사하는 프로젝트를 해 보고도 싶네요.

패스워드 크래킹을 하는데, 왜 해시 값을 추출해야 할까에 대해 질문하려고 했는데, 이번에도 아쉽게 질문하지 못했습니다. 발표가 끝나고 스스로 찾아 보니, 여러 개의 알려진 비밀번호에 해시를 수행하고, 이 해시를 실제 압축 파일의 것과 비교함으로써 레인보우테이블 공격을 수행하는 것으로 보이네요!

### 사설 업체 디지털 포렌식 데이터 관리 [성신여대 HASH 이은민 김희주님]

---

하드디스크 저장 매체의 저장 방법을 학습한 뒤, FTK Imager를 활요용하여 하드디스크 복구 실습을 진행하셨다고 합니다. 그리고 이 방법에 대해 다들 잘 알고 있을테니 자세한 설명은 해주지 않으셨습니다(저는 몰라요 ㅜㅜ).

그리고, Master Boot Record(MBR)을 감염 및 부팅 불가하게 만드는 랜섬웨어인 Petya를 활용하여, MBR 영역을 오염시킨 뒤에 이를 다시 복구하는 작업을 하셨습니다. MBR 영역이 0x37로 XOR 연산이 수행되며, 실제 원본 값은 0x7000에 숨기는 방식으로 컴퓨터가 부팅되자마자 랜섬웨어를 바치라는 문구가 뜬 뒤 멈추도록 설계한 랜섬웨어로 보였습니다.

이를 해결하시기 위해, Petya가 숨겨놓은 데이터를 찾고, 0x37으로 XOR 연산을 수행하여 복구를 수행하셨습니다. 그러나, 그렇게 복구를 수행하였음에도 불구하고 실제 부팅은 되지 않았다고 합니다.

![MBR](2.png)

Petya 랜섬웨어에는 컴퓨터가 부팅될 때 실행되는 부트 코드만 변경된 것이 아니라, 파티션 또한 암호화를 수행하는 로직이 포함되어 있기 때문이라고 설명해 주셨습니다. 악성 코드의 로직을 분석하고, 이를 그대로 역산하여 복구하는 작업도 재밌어 보였습니다.

### [특강] 포렌식 케이스 사례 소개 - Gwisin RansomWare [Ahnlab 정현우님]

---

정현우님의 발표를 가장 열심히 들었던 것 같습니다. 2021년부터 활발히 활동하였던 귀신(Gwisin RansomWare) 랜섬웨어에 대해 소개해주시는 것뿐 아니라, 포렌식 분석 업무에서 일반적인 포렌식과 DFIR(Digital Forensics and Incident Response, 줄여서 IR?)의 차이점, 그리고 실제 귀신 랜섬웨어가 감염되었을 때의 사건을 침투부터 시스템 장악까지에 걸친 시나리오를 설명해주셨습니다. 저는 22년 6월에 KISA 정보보호클러스터에서 침해사고 대응 훈련을 받은 경험이 있었는데, 그때의 공격 과정과 귀신 랜섬웨어 공격자의 공격 과정을 비교해보면서 들으니 더욱 실감나게 들을 수 있었던 것 같습니다.

랜섬웨어에 대한 대응 방안도 이야기해 주셨는데, 기업 단에서 할 수 있는 것은 크게 계정 관리, 접근 관리, 백신 업데이트 및 행위 탐지, 그리고 주요 서버 데이터 백업을 이야기해주셨습니다. 그중에서, 계정 관리에서는 관리자 계정 로그온 행위를 모니터링하고, 접근 관리에서는 내부 시스템 간 접근 또한 제어를 해야 한다고 하셨는데, 이에 대해 지금 진행 중인 졸업 프로젝트에서 참고할 수 있을 것 같아 따로 필기해 뒀습니다.

### APT 그룹 공격 기법과 아티팩트 연관성 분석 [F-Active 하정희님]

---

APT 그룹이 공격을 수행한 뒤, 시스템에 남게 되는 아티팩트(Artifact)에 대한 연관성을 분석하는 프로젝트에 대해 발표해주셨습니다. 먼저 직접 APT 공격 관련 레포트 및 TTPs(Tactics, Techniques and Procedures)를 수집하고, 이 TTP 정보를 바탕으로 공격 행위를 리스트업하고, 실제로 그 공격 행위를 재현하고 아티팩트를 분석한 내용을 공유해 주셨습니다. 보통 보고서는 IoC(Indicators of Compromise)라는 침해사고 지표로 나타나는데, 프로젝트 진행 시에는 최대한 TTPs 위주로 재현 가능한 보고서에 대해 리스트업 하셨다고 합니다.

5개 정도의 사례에 대해 재현 및 분석을 진행하신 듯 보였는데, Incognito CTF에 참가하느라 + 포렌식에 큰 관심이 없었어서 이 이후로는 제대로 듣지 못했네요.. 죄송합니다. 정말 포렌식, 그중에서도 침해사고대응에 관심이 있는 학생에게는 알찬 정보였을 것이 문외한이어도 확인 가능한 수준의 프로젝트였습니다. 직장인임에도 F-Active라는 단체를 꾸려서, 프로젝트 연구 및 포렌식 대회 출전을 하시다니, 정말 대단하다는 생각이 들었습니다.

---

모두들 짧은 기간 동안 열심히 프로젝트를 했다는 것이 여실히 느껴지는 발표였습니다. 첫 날에도 좋은 주제로 발표들이 진행되었던데, 이에 참여하지 못해서 많이 아쉬움이 남네요. 또, CTF에 참여하느라 네트워킹 시간에 제대로 사람들과 이야기하지 못한 것이 정말 아깝다는 생각이 듭니다. 올해 8월에도 Incognito 컨퍼런스가 열린다고 하는데, 저는 7월에 갈 예정이라 아쉽게 참여하지 못하지만, 혹시 이 글을 읽으면서 참여를 고민하시는 분이라면 꼭 참여해보시길 권유드립니다! 정보보안과 해킹에 관심이 많은 사람들이 한 군데 모여 서로의 관심사에 대해 얘기를 나눌 수 있고, 그 과정에서 영감을 받을 수도 있으니까요!